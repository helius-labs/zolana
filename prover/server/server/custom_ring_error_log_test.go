package server

import (
	"bytes"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"zolana/prover/logging"
	"zolana/prover/prover/common"
	customring "zolana/prover/prover/custom_ring"

	"github.com/rs/zerolog"
)

const customRingQueue = "zk_custom_ring_queue"

// A custom-ring failure reaches the client as errCustomRingProof and nothing
// else, because its cause can carry private inputs. The same cause has to land
// in the server log, on the line that names the job, or an operator is left
// with "custom ring proof failed" and no way to find out why. Each case drives
// a job through processJobs and checks both ends.
func TestCustomRingQueueFailureLogsCauseAndRedactsResponse(t *testing.T) {
	cases := []struct {
		name       string
		payload    []byte
		keyManager *common.LazyKeyManager
		cause      string
		code       string
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
			code:    "malformed_body",
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
			_, rq := newTestQueue(t)
			logs := captureLogs(t)

			runOneJob(t, rq, customRingQueue, WorkerConfig{Keys: c.keyManager}, &ProofJob{ID: "job-1", Payload: c.payload})

			assertCauseLoggedOnceWithJob(t, logs, c.cause, "job-1")
			assertClientSees(t, rq, "job-1", errCustomRingProof.Error(), c.code)
		})
	}
}

// A failed Prove comes back from dispatch as a redacted *Error that carries
// its cause, which processJobs hands to proofFailed. Running a real custom-ring
// Prove needs that ring's proving key, so these cases start at proofFailed. The
// cause and the job id have to share one log line, while the client reads the
// redacted message and the code, never the cause. An indexed job is redacted to
// errIndexedProof on every queue, and still logs the cause.
func TestQueueProvingFailureLogsCauseOnceWithJob(t *testing.T) {
	const cause = "prove: constraint #7 is not satisfied"
	cases := []struct {
		name    string
		queue   string
		indexed bool
		failure *Error
		want    error
	}{
		{"custom ring", customRingQueue, false, customRingFailure(provingError(errors.New(cause))), errCustomRingProof},
		{"indexed custom ring", customRingQueue, true, customRingFailure(provingError(errors.New(cause))), errIndexedProof},
		{"indexed transfer", "zk_transfer_queue", true, provingError(errors.New(cause)), errIndexedProof},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, rq := newTestQueue(t)
			logs := captureLogs(t)
			worker := newQueueWorker(c.queue, WorkerConfig{Queue: rq, Ready: readyNow()}, NewExecution(1))
			job := &ProofJob{ID: "job-1", Indexed: c.indexed, Payload: validCustomRingBasePayload(t), CreatedAt: time.Now()}

			worker.proofFailed(job, "", c.failure, time.Second)

			assertCauseLoggedOnceWithJob(t, logs, cause, "job-1")
			assertClientSees(t, rq, "job-1", c.want.Error(), "proving_error")
		})
	}
}

// Redaction is specific to the custom-ring queue and to indexed jobs; other
// queues keep telling the client what went wrong.
func TestNonCustomRingQueueFailureStaysUnredacted(t *testing.T) {
	_, rq := newTestQueue(t)
	captureLogs(t)

	runOneJob(t, rq, "zk_transfer_queue", WorkerConfig{}, &ProofJob{ID: "job-1", Payload: []byte(`{"circuitType":"custom-ring-base"}`)})

	assertClientSees(t, rq, "job-1", "circuit custom-ring-base cannot run on zk_transfer_queue", "")
}

// The sync path redacts exactly what the queue path redacts and logs the
// withheld cause the same way. A failure the client reads in full is not
// logged.
func TestSyncProofFailureLogsCauseAndRedactsResponse(t *testing.T) {
	const cause = "prove: constraint #7 is not satisfied"
	ring, transfer := common.CustomRingBaseCircuitType, common.TransferConfidentialCircuitType
	cases := []struct {
		name    string
		circuit common.CircuitType
		indexed bool
		failure *Error
		message string
		logged  int
	}{
		{"custom ring", ring, false, customRingFailure(provingError(errors.New(cause))), errCustomRingProof.Error(), 1},
		{"indexed custom ring", ring, true, customRingFailure(provingError(errors.New(cause))), errIndexedProof.Error(), 1},
		{"indexed transfer", transfer, true, provingError(errors.New(cause)), errIndexedProof.Error(), 1},
		{"transfer", transfer, false, provingError(errors.New(cause)), cause, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			logs := captureLogs(t)

			response := proveHandler{indexed: c.indexed}.syncProofFailure(c.circuit, c.failure)

			if logged := len(logLinesMentioning(t, logs, cause)); logged != c.logged {
				t.Errorf("cause logged %d times, want %d:\n%s", logged, c.logged, logs.String())
			}
			assertResponse(t, response, c.message, "proving_error")
		})
	}
}

func TestSyncPanicLogsValueAndRedactsResponse(t *testing.T) {
	const value = "index out of range [3] with length 2"
	const prefix = "internal error during proof processing: "
	ring, transfer := common.CustomRingBaseCircuitType, common.TransferConfidentialCircuitType
	cases := []struct {
		circuit common.CircuitType
		indexed bool
		message string
	}{
		{transfer, false, prefix + value},
		{ring, false, prefix + errCustomRingProof.Error()},
		{transfer, true, prefix + errIndexedProof.Error()},
		{ring, true, prefix + errIndexedProof.Error()},
	}

	for _, c := range cases {
		logs := captureLogs(t)

		response := proveHandler{indexed: c.indexed}.syncPanicFailure(c.circuit, value)

		if logged := len(logLinesMentioning(t, logs, value)); logged != 1 {
			t.Errorf("%s indexed=%v: panic value logged %d times, want 1:\n%s", c.circuit, c.indexed, logged, logs.String())
		}
		assertResponse(t, response, c.message, "unexpected_error")
	}
}

// A custom-ring request that does not decode fails before any proving key is
// needed, so this one runs through the real sync handler. The client keeps the
// malformed_body code, which says the request was at fault, but not the decode
// error, which can quote request values.
func TestSyncCustomRingDecodeFailureIsRedacted(t *testing.T) {
	const cause = "publicInputHash is not canonical hex"
	logs := captureLogs(t)
	readiness := NewReadiness()
	readiness.MarkReady()
	handler := proveHandler{readiness: readiness, admission: newSyncAdmission(1)}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/prove", strings.NewReader(`{"circuitType":"custom-ring-base","publicInputHash":"0x12"}`)))

	body := decodeError(t, response)
	if response.Code != http.StatusBadRequest || body["code"] != "malformed_body" || body["message"] != errCustomRingProof.Error() {
		t.Errorf("client sees %d %v", response.Code, body)
	}
	if logged := len(logLinesMentioning(t, logs, cause)); logged != 1 {
		t.Errorf("cause logged %d times, want 1:\n%s", logged, logs.String())
	}
}

// runOneJob enqueues a job, lets one worker pick it up, and waits for the
// proving goroutine to finish, on the error, the panic, and the resolution
// failure path.
func runOneJob(t *testing.T, rq *RedisQueue, queueName string, config WorkerConfig, job *ProofJob) {
	t.Helper()
	config.Queue, config.Ready = rq, readyNow()
	worker := newQueueWorker(queueName, config, NewExecution(1))
	job.Type, job.CreatedAt = "zk_proof", time.Now()
	if err := rq.EnqueueProof(queueName, job); err != nil {
		t.Fatalf("EnqueueProof: %v", err)
	}
	if job.Indexed {
		// dispatchIndexed takes a resolving slot before each pop, and resolve
		// gives it back.
		worker.resolving <- struct{}{}
	}

	worker.processJobs(job.Indexed)

	finished := make(chan struct{})
	go func() { worker.pending.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("proof job did not finish")
	}
}

// assertClientSees checks the failure in both places a client can read it: the
// job metadata behind the status endpoint, and zk_failed_queue. An empty code
// means the failure carries none.
func assertClientSees(t *testing.T, rq *RedisQueue, jobID, message, code string) {
	t.Helper()
	meta, err := rq.GetJobMeta(jobID)
	if err != nil || meta == nil {
		t.Fatalf("GetJobMeta: meta=%v err=%v", meta, err)
	}
	failure, ok := meta["failure"].(map[string]interface{})
	if !ok {
		t.Fatalf("job metadata records no failure: %v", meta)
	}

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

	for where, seen := range map[string]map[string]interface{}{"job metadata": failure, "zk_failed_queue": details} {
		if seen["error"] != message {
			t.Errorf("%s: client sees %q, want %q", where, seen["error"], message)
		}
		if seenCode, _ := seen["code"].(string); seenCode != code {
			t.Errorf("%s: code = %q, want %q", where, seenCode, code)
		}
	}
}

// assertResponse checks what a sync client reads: MarshalJSON sends only the
// code, the message, and a registry member.
func assertResponse(t *testing.T, response *Error, message, code string) {
	t.Helper()
	if response.Message != message || response.Code != code {
		t.Errorf("client sees %q (%s), want %q (%s)", response.Message, response.Code, message, code)
	}
}

// assertCauseLoggedOnceWithJob checks that exactly one log line mentions the
// cause and that the same line names the job.
func assertCauseLoggedOnceWithJob(t *testing.T, logs *syncBuffer, cause, jobID string) {
	t.Helper()
	lines := logLinesMentioning(t, logs, cause)
	if len(lines) != 1 || lines[0]["job_id"] != jobID {
		t.Errorf("want one log line with the cause %q and job_id %q:\n%s", cause, jobID, logs.String())
	}
}

func logLinesMentioning(t *testing.T, logs *syncBuffer, text string) []map[string]interface{} {
	t.Helper()
	var lines []map[string]interface{}
	for _, line := range strings.Split(logs.String(), "\n") {
		if !strings.Contains(line, text) {
			continue
		}
		var fields map[string]interface{}
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			t.Fatalf("log line %q is not JSON: %v", line, err)
		}
		lines = append(lines, fields)
	}
	return lines
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
