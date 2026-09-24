package server

import (
	"bytes"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
	"zolana/prover/logging"
	"zolana/prover/prover/common"
	customring "zolana/prover/prover/custom_ring"

	"github.com/alicebob/miniredis/v2"
	"github.com/rs/zerolog"
)

const customRingQueue = "zk_custom_ring_queue"

// A custom-ring failure reaches the client as errCustomRingProof and nothing
// else, because its cause can carry private inputs. The same cause has to land
// in the server log, or an operator is left with "custom ring proof failed"
// and no way to find out why. Each case drives a job through processJobs and
// checks both ends.
func TestCustomRingQueueFailureLogsCauseAndRedactsResponse(t *testing.T) {
	cases := []struct {
		name       string
		payload    []byte
		keyManager *common.LazyKeyManager
		cause      string
	}{
		{
			name:    "request meta does not parse",
			payload: []byte(`[1]`),
			cause:   "failed to parse proof request",
		},
		{
			name:    "circuit belongs to another queue",
			payload: []byte(`{"circuitType":"transfer-confidential"}`),
			cause:   "circuit transfer-confidential cannot run on zk_custom_ring_queue",
		},
		{
			name:    "custom-ring request does not decode",
			payload: []byte(`{"circuitType":"custom-ring-base","publicInputHash":"0x12"}`),
			cause:   "publicInputHash is not canonical hex",
		},
		{
			// A zero-value key manager has no loading map, so the first key
			// lookup panics: the cheapest way to reach the recover path with a
			// request that decodes.
			name:       "proof generation panics",
			payload:    validCustomRingBasePayload(t),
			keyManager: &common.LazyKeyManager{},
			cause:      "panic: assignment to entry in nil map",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rq := newTestRedisQueue(t)
			logs := captureLogs(t)

			runOneJob(t, rq, customRingQueue, c.keyManager, "job-1", c.payload)

			if !strings.Contains(logs.String(), c.cause) {
				t.Errorf("server log is missing the cause %q:\n%s", c.cause, logs.String())
			}
			for _, clientVisible := range clientVisibleFailure(t, rq, "job-1") {
				if clientVisible != errCustomRingProof.Error() {
					t.Errorf("client sees %q, want %q", clientVisible, errCustomRingProof.Error())
				}
			}
		})
	}
}

// Redaction is specific to the custom-ring queue; other queues keep telling the
// client what went wrong.
func TestNonCustomRingQueueFailureStaysUnredacted(t *testing.T) {
	rq := newTestRedisQueue(t)
	captureLogs(t)

	runOneJob(t, rq, "zk_transfer_queue", nil, "job-1", []byte(`{"circuitType":"custom-ring-base"}`))

	const cause = "circuit custom-ring-base cannot run on zk_transfer_queue"
	for _, clientVisible := range clientVisibleFailure(t, rq, "job-1") {
		if clientVisible != cause {
			t.Errorf("client sees %q, want %q", clientVisible, cause)
		}
	}
}

func TestSyncCustomRingProvingErrorLogsCauseAndRedactsResponse(t *testing.T) {
	const cause = "prove: constraint #7 is not satisfied"
	logs := captureLogs(t)

	response := customRingProvingError(common.CustomRingBaseCircuitType, errors.New(cause))

	if !strings.Contains(logs.String(), cause) {
		t.Errorf("server log is missing the cause %q:\n%s", cause, logs.String())
	}
	if response.Message != errCustomRingProof.Error() {
		t.Errorf("client sees %q, want %q", response.Message, errCustomRingProof.Error())
	}
	if response.Code != "proving_error" {
		t.Errorf("response code = %q, want proving_error", response.Code)
	}
}

func newTestRedisQueue(t *testing.T) *RedisQueue {
	t.Helper()
	rq, err := NewRedisQueue("redis://" + miniredis.RunT(t).Addr() + "/0")
	if err != nil {
		t.Fatalf("NewRedisQueue: %v", err)
	}
	return rq
}

// runOneJob enqueues a job, lets one worker pick it up, and waits for the
// proving goroutine to release its semaphore slot, which it does last on both
// the error and the panic path.
func runOneJob(t *testing.T, rq *RedisQueue, queueName string, keyManager *common.LazyKeyManager, jobID string, payload []byte) {
	t.Helper()
	worker := &BaseQueueWorker{
		queue:               rq,
		keyManager:          keyManager,
		stopChan:            make(chan struct{}),
		queueName:           queueName,
		processingQueueName: queueName + "_processing",
		maxConcurrency:      1,
		semaphore:           make(chan struct{}, 1),
	}
	job := &ProofJob{ID: jobID, Type: "zk_proof", Payload: payload, CreatedAt: time.Now()}
	if err := rq.EnqueueProof(queueName, job); err != nil {
		t.Fatalf("EnqueueProof: %v", err)
	}

	worker.processJobs()

	deadline := time.Now().Add(10 * time.Second)
	for len(worker.semaphore) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("proof job did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// clientVisibleFailure returns the error text from both places a client can
// read a failure: the job metadata behind the status endpoint, and
// zk_failed_queue.
func clientVisibleFailure(t *testing.T, rq *RedisQueue, jobID string) []string {
	t.Helper()
	meta, err := rq.GetJobMeta(jobID)
	if err != nil || meta == nil {
		t.Fatalf("GetJobMeta: meta=%v err=%v", meta, err)
	}
	failure, ok := meta["failure"].(map[string]interface{})
	if !ok {
		t.Fatalf("job metadata records no failure: %v", meta)
	}
	metaError, _ := failure["error"].(string)

	entries, err := rq.Client.LRange(rq.Ctx, "zk_failed_queue", 0, -1).Result()
	if err != nil || len(entries) != 1 {
		t.Fatalf("zk_failed_queue: entries=%d err=%v", len(entries), err)
	}
	var failed ProofJob
	if err := json.Unmarshal([]byte(entries[0]), &failed); err != nil {
		t.Fatalf("decode failed job: %v", err)
	}
	var details map[string]interface{}
	if err := json.Unmarshal(failed.Payload, &details); err != nil {
		t.Fatalf("decode failure details: %v", err)
	}
	queueError, _ := details["error"].(string)

	return []string{metaError, queueError}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLogs redirects the process logger for the rest of the test.
func captureLogs(t *testing.T) *syncBuffer {
	t.Helper()
	logs := &syncBuffer{}
	previous := *logging.Logger()
	*logging.Logger() = zerolog.New(logs)
	t.Cleanup(func() { *logging.Logger() = previous })
	return logs
}

func validCustomRingBasePayload(t *testing.T) []byte {
	t.Helper()
	params := &customring.BaseParameters{
		PublicInputHash: big.NewInt(1),
		PrivateTxHash:   big.NewInt(2),
		NOut:            1,
	}
	for i := range params.TxViewingSk {
		params.TxViewingSk[i] = byte(i + 1)
		params.EphSk[i] = byte(0x20 + i)
	}
	curve := elliptic.P256().Params()
	copy(params.AuditorPk[:], elliptic.Marshal(elliptic.P256(), curve.Gx, curve.Gy))
	for i := range params.Outputs {
		params.Outputs[i] = customring.AuditOpening{
			Domain: big.NewInt(0), TreeID: big.NewInt(0), OwnerHash: big.NewInt(0),
			Asset: big.NewInt(0), Amount: big.NewInt(0), Blinding: big.NewInt(0),
			DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0),
		}
	}
	payload, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal base parameters: %v", err)
	}
	if _, err := customring.DecodeRequest(common.CustomRingBaseCircuitType, payload); err != nil {
		t.Fatalf("fixture does not decode: %v", err)
	}
	return payload
}
