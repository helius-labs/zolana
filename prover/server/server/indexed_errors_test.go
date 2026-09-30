package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"zolana/prover/prover/common"
	"zolana/prover/prover/indexed"
	transfer "zolana/prover/prover/transfer_eddsa_only"

	"github.com/prometheus/client_golang/prometheus/testutil"
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
	member := indexed.Hash{31: 7}
	cases := []struct {
		err        error
		status     int
		code       string
		retryAfter int
		member     string
	}{
		{indexed.ErrIndexerNotReady, http.StatusServiceUnavailable, "indexer_not_ready", notReadyRetryAfterSecs, ""},
		{&indexed.UnregisteredMemberError{Member: member}, http.StatusUnprocessableEntity, "registry_member_missing", 0, member.String()},
		{errors.New("upstream detail"), http.StatusBadGateway, "indexer_unavailable", 0, ""},
	}
	for _, c := range cases {
		failure := indexedFailure(c.err)
		if failure.StatusCode != c.status || failure.Code != c.code || failure.RetryAfter != c.retryAfter || failure.Member != c.member {
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
	member := indexed.Hash{31: 7}
	details := worker.failureDetails(job, indexedFailure(&indexed.UnregisteredMemberError{Member: member}))
	if details["code"] != "registry_member_missing" || details["member"] != member.String() || details["error"] != errIndexedProof.Error() {
		t.Fatalf("unregistered member details %v", details)
	}
	details = worker.failureDetails(job, indexedFailure(indexed.ErrIndexerNotReady))
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
