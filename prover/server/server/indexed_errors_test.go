package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/helius-labs/zolana/prover/server/logging"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	"github.com/helius-labs/zolana/prover/server/prover/indexed"
	transfer "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"
)

func indexedTransferRequest(t *testing.T) []byte {
	t.Helper()
	prepared, err := json.Marshal(transfer.TransferParametersJSON{
		CircuitType: common.TransferConfidentialCircuitType,
		NInputs:     2, NOutputs: 2, BlindingSeed: "0x1",
		PublicAssets: []string{"0x0", "0x0", "0x0"}, PublicAmounts: []string{"0x0", "0x0", "0x0"},
		Inputs:  []transfer.InputParamsJSON{{IsDummy: "0x0", Nullifier: "0x64"}, {IsDummy: "0x1", Nullifier: "0xc8"}},
		Outputs: []transfer.OutputParamsJSON{{}, {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var commitment indexed.Hash
	commitment[31] = 42
	request := indexed.Request{
		CircuitType: common.TransferConfidentialCircuitType, Prepared: prepared,
		Trees:        []indexed.Tree{{Address: (indexed.Hash{}).String(), ID: 0}},
		Inputs:       []indexed.Lookup{{TreeSlot: 0, Commitment: &commitment}, {TreeSlot: 0}},
		PublicInputs: make([]string, 17),
	}
	for index := range request.PublicInputs {
		request.PublicInputs[index] = "0x0"
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := indexed.Validate(data); err != nil {
		t.Fatal(err)
	}
	return data
}

func decodeError(t *testing.T, response *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body %q is not JSON", response.Body.String())
	}
	return body
}

func TestIndexedFailureCodes(t *testing.T) {
	cases := []struct {
		err        error
		status     int
		code       string
		retryAfter int
	}{
		{indexed.ErrIndexerNotReady, http.StatusServiceUnavailable, "indexer_not_ready", notReadyRetryAfterSecs},
		{errors.New("upstream detail"), http.StatusBadGateway, "indexer_unavailable", 0},
	}
	for _, c := range cases {
		failure := indexedFailure(c.err)
		if failure.StatusCode != c.status || failure.Code != c.code || failure.RetryAfter != c.retryAfter {
			t.Fatalf("%v mapped to %+v", c.err, failure)
		}
		if bytes.Contains([]byte(failure.Message), []byte("upstream detail")) {
			t.Fatal("indexer detail reached the client")
		}
	}
}

func TestQueuedIndexedFailuresCarryTheirCode(t *testing.T) {
	worker := &BaseQueueWorker{queueName: "zk_transfer_queue"}
	job := &ProofJob{Indexed: true, Payload: json.RawMessage(`{"circuitType":"transfer"}`)}
	details := worker.failureDetails(job, indexedFailure(indexed.ErrIndexerNotReady))
	if details["code"] != "indexer_not_ready" || details["error"] != indexed.ErrIndexerNotReady.Error() {
		t.Fatalf("not ready details %v", details)
	}
}

func TestNotReadyResponsesAreRetryableJSON(t *testing.T) {
	readiness := NewReadiness()
	for method, handler := range map[string]http.Handler{http.MethodGet: readiness, http.MethodPost: proveHandler{readiness: readiness}} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(method, "/prove", nil))
		if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") == "" || decodeError(t, response)["code"] != "prover_not_ready" {
			t.Fatalf("not ready response %d %v %q", response.Code, response.Header(), response.Body.String())
		}
	}
}

func TestIndexedRouteWithoutIndexerIsNotFound(t *testing.T) {
	readiness := NewReadiness()
	readiness.MarkReady()
	response := httptest.NewRecorder()
	proveHandler{readiness: readiness, indexed: true}.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/prove/indexed", bytes.NewReader(indexedTransferRequest(t))))
	if response.Code != http.StatusNotFound || decodeError(t, response)["code"] != "indexer_unconfigured" {
		t.Fatalf("unconfigured response %d %q", response.Code, response.Body.String())
	}
}

func TestHealthReportsIndexer(t *testing.T) {
	for _, configured := range []bool{false, true} {
		response := httptest.NewRecorder()
		healthHandler{indexed: configured}.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health", nil))
		var body struct{ Indexed *bool }
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Indexed == nil || *body.Indexed != configured {
			t.Fatalf("health body %q", response.Body.String())
		}
	}
}

func TestShedIndexedRequestNeverReachesTheIndexer(t *testing.T) {
	var calls atomic.Int64
	photon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer photon.Close()
	resolver, err := indexed.NewResolver(indexed.Config{URL: photon.URL, Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	readiness := NewReadiness()
	readiness.MarkReady()
	admission := newSyncAdmission(1)
	admission.waiting.Store(admission.maxWait)
	handler := proveHandler{readiness: readiness, indexer: resolver, indexed: true, transferExecution: &Execution{admission: admission}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/prove/indexed", bytes.NewReader(indexedTransferRequest(t))))
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" || calls.Load() != 0 {
		t.Fatalf("shed response %d after %d indexer calls", response.Code, calls.Load())
	}
	if admission.waiting.Load() != admission.maxWait {
		t.Fatal("shed request changed the waiting count")
	}
}

func TestPanickingProofRequestCountsAsFailure(t *testing.T) {
	before := testutil.ToFloat64(ProofPanicsTotal.WithLabelValues("unknown"))
	handler := observeProofHTTP("panic", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic was swallowed")
			}
		}()
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/prove", nil))
	}()
	if testutil.ToFloat64(ProofPanicsTotal.WithLabelValues("unknown")) != before+1 {
		t.Fatal("panic was not counted")
	}
	for _, c := range []struct {
		status    int
		retryable bool
		label     string
	}{{200, false, "2xx"}, {422, false, "4xx"}, {500, false, "5xx"}, {502, false, "upstream"}, {503, true, "unavailable"}, {503, false, "5xx"}} {
		if got := statusLabel(c.status, c.retryable); got != c.label {
			t.Fatalf("status %d retryable %v labelled %s", c.status, c.retryable, got)
		}
	}
}

func failingPhoton(t *testing.T) *indexed.Resolver {
	t.Helper()
	photon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(photon.Close)
	resolver, err := indexed.NewResolver(indexed.Config{URL: photon.URL, Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

// A client told indexer_unavailable cannot see why, so the log line has to
// carry the resolver's error, next to the job on the queue path.
func TestIndexerUnavailableLogsCause(t *testing.T) {
	const cause = "indexer response status 500"

	t.Run("queue", func(t *testing.T) {
		_, rq := newTestQueue(t)
		logs := captureLogs(t)

		runOneJob(t, rq, "zk_transfer_queue", WorkerConfig{Indexer: failingPhoton(t)}, &ProofJob{ID: "job-1", Indexed: true, Payload: indexedTransferRequest(t)})

		assertCauseLoggedOnceWithJob(t, logs, cause, "job-1")
		assertClientSees(t, rq, "job-1", errIndexedProof.Error(), "indexer_unavailable")
	})

	t.Run("sync", func(t *testing.T) {
		logs := captureLogs(t)
		readiness := NewReadiness()
		readiness.MarkReady()
		handler := proveHandler{readiness: readiness, indexer: failingPhoton(t), indexed: true, transferExecution: &Execution{admission: newSyncAdmission(1)}}

		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/prove/indexed", bytes.NewReader(indexedTransferRequest(t))))

		if body := decodeError(t, response); response.Code != http.StatusBadGateway || body["code"] != "indexer_unavailable" || bytes.Contains(response.Body.Bytes(), []byte(cause)) {
			t.Errorf("client sees %d %v", response.Code, body)
		}
		if logged := len(logLinesMentioning(t, logs, cause)); logged != 1 {
			t.Errorf("cause logged %d times, want 1:\n%s", logged, logs.String())
		}
	})
}

// A failed Prove comes back from dispatch as a redacted *Error that carries
// its cause, which processJobs hands to proofFailed. The cause and the job id
// have to share one log line, while the client reads the redacted message and
// the code, never the cause. An indexed job is redacted to errIndexedProof and
// still logs the cause.
func TestQueueProvingFailureLogsCauseOnceWithJob(t *testing.T) {
	const cause = "prove: constraint #7 is not satisfied"
	_, rq := newTestQueue(t)
	logs := captureLogs(t)
	worker := newQueueWorker("zk_transfer_queue", WorkerConfig{Queue: rq, Ready: readyNow()}, NewExecution(1))
	job := &ProofJob{ID: "job-1", Indexed: true, Payload: indexedTransferRequest(t), CreatedAt: time.Now()}

	worker.proofFailed(job, "", provingError(errors.New(cause)), time.Second)

	assertCauseLoggedOnceWithJob(t, logs, cause, "job-1")
	assertClientSees(t, rq, "job-1", errIndexedProof.Error(), "proving_error")
}

// The sync path redacts exactly what the queue path redacts and logs the
// withheld cause the same way. A failure the client reads in full is not
// logged.
func TestSyncProofFailureLogsCauseAndRedactsResponse(t *testing.T) {
	const cause = "prove: constraint #7 is not satisfied"
	transfer := common.TransferConfidentialCircuitType
	cases := []struct {
		name    string
		circuit common.CircuitType
		indexed bool
		failure *Error
		message string
		logged  int
	}{
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
	transfer := common.TransferConfidentialCircuitType
	cases := []struct {
		circuit common.CircuitType
		indexed bool
		message string
	}{
		{transfer, false, prefix + value},
		{transfer, true, prefix + errIndexedProof.Error()},
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
// code and the message.
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
