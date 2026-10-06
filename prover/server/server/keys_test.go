package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"zolana/prover/prover/common"
	"zolana/prover/prover/indexed"
	transfer "zolana/prover/prover/transfer_eddsa_only"
)

func servedKeys(t *testing.T, patterns ...string) *ServedKeys {
	t.Helper()
	served, err := ParseServedKeys(patterns)
	if err != nil {
		t.Fatal(err)
	}
	return served
}

func TestServedKeysDefaultToEveryKey(t *testing.T) {
	names := servedKeys(t).Names()
	if len(names) != len(common.KeyFiles()) || !slices.Contains(names, "batch_address-append_40_250") {
		t.Fatalf("default served keys %v", names)
	}
}

func TestServedKeysMatchPatternsOverKeyNames(t *testing.T) {
	served := servedKeys(t, "*_49_*", "*_51_*", "batch_address-append_40_250")
	for file, want := range map[string]bool{
		"transfer_p256_ring_49_2.key":     true,
		"merge_51_1.key":                  true,
		"batch_address-append_40_250.key": true,
		"transfer_confidential_1_2.key":   false,
		"merge_24_1.key":                  false,
		"batch_address-append_40_10.key":  false,
	} {
		if served.Serves(file) != want {
			t.Errorf("serves %s = %v, want %v", file, !want, want)
		}
	}
}

func TestServedKeysRejectPatternsThatMatchNothing(t *testing.T) {
	for _, pattern := range []string{"trasnfer_*", "transfer_confidential_1_2.key", "["} {
		if _, err := ParseServedKeys([]string{pattern}); err == nil {
			t.Errorf("pattern %q accepted", pattern)
		}
	}
}

func TestKeyAdmission(t *testing.T) {
	onlyMerges := servedKeys(t, "merge_*")
	for name, test := range map[string]struct {
		admission keyAdmission
		file      string
		code      string
	}{
		"path key":                           {keyAdmission{expected: "merge_24_1.key"}, "merge_24_1.key", ""},
		"another key than the path":          {keyAdmission{expected: "merge_24_1.key"}, "merge_51_1.key", "proving_key_mismatch"},
		"unsupported shape on a key path":    {keyAdmission{expected: "merge_24_1.key"}, "", "proving_key_mismatch"},
		"job without a path key, served":     {keyAdmission{served: onlyMerges}, "merge_51_1.key", ""},
		"job without a path key, not served": {keyAdmission{served: onlyMerges}, "transfer_ring_2_4.key", "proving_key_not_served"},
		// Left to the key manager, which reports the unsupported shape.
		"job without a path key, unsupported shape": {keyAdmission{served: onlyMerges}, "", ""},
	} {
		failure := test.admission.admit(test.file)
		code := ""
		if failure != nil {
			code = failure.Code
		}
		if code != test.code {
			t.Errorf("%s: got %q, want %q", name, code, test.code)
		}
	}
}

// A complete transfer-confidential 2x2 body.
func transferRequest(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(transfer.TransferParametersJSON{
		CircuitType: common.TransferConfidentialCircuitType,
		NInputs:     2, NOutputs: 2, BlindingSeed: "0x1",
		PublicAssets: []string{"0x0", "0x0", "0x0"}, PublicAmounts: []string{"0x0", "0x0", "0x0"},
		Inputs:  []transfer.InputParamsJSON{{IsDummy: "0x0", Nullifier: "0x64"}, {IsDummy: "0x1", Nullifier: "0xc8"}},
		Outputs: []transfer.OutputParamsJSON{{}, {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// proofMux serves the proof paths the way RunEnhanced does. It has a queue, so
// the status path is published, but proves in the response. The key manager
// has no keys, so a request that passes admission fails on the missing key
// file rather than proving.
func proofMux(t *testing.T, served *ServedKeys) *http.ServeMux {
	t.Helper()
	_, queue := newTestQueue(t)
	readiness := NewReadiness()
	readiness.MarkReady()
	mux := http.NewServeMux()
	registerProofPaths(mux, proveHandler{
		readiness:         readiness,
		keyManager:        common.NewLazyKeyManager(t.TempDir(), &common.DownloadConfig{}),
		transferExecution: NewExecution(1),
		redisQueue:        queue,
		served:            served,
		admission:         newSyncAdmission(1),
	})
	return mux
}

func post(mux *http.ServeMux, path string, body []byte) *httptest.ResponseRecorder {
	return serve(mux, http.MethodPost, path, body)
}

func serve(mux *http.ServeMux, method, path string, body []byte) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(method, path, bytes.NewReader(body)))
	return response
}

func errorCode(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct{ Code string }
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body %q: %v", response.Body.String(), err)
	}
	return body.Code
}

func TestKeyPathHoldsTheBodyToItsKey(t *testing.T) {
	mux := proofMux(t, nil)
	for _, prefix := range []string{"", gatewayPrefix} {
		response := post(mux, prefix+"/prove/transfer_confidential_1_2", transferRequest(t))
		if response.Code != http.StatusBadRequest || errorCode(t, response) != "proving_key_mismatch" {
			t.Fatalf("%s: mismatched body got %d %q", prefix, response.Code, response.Body.String())
		}
		// The matching key gets past admission to the key manager, which has no
		// key file to load.
		response = post(mux, prefix+"/prove/transfer_confidential_2_2", transferRequest(t))
		if errorCode(t, response) != "proving_error" || !strings.Contains(response.Body.String(), "transfer_confidential_2_2.key") {
			t.Fatalf("%s: matching body got %d %q", prefix, response.Code, response.Body.String())
		}
	}
}

func TestKeyPathRefusesUnknownAndUnservedKeys(t *testing.T) {
	mux := proofMux(t, servedKeys(t, "merge_*"))
	for _, test := range []struct{ method, path, code string }{
		{http.MethodPost, "/prove/transfer_confidential_9_9", "unknown_proving_key"},
		{http.MethodPost, "/prove/transfer_confidential_2_2", "proving_key_not_served"},
		{http.MethodPost, "/prove/transfer_confidential_2_2/indexed", "proving_key_not_served"},
		{http.MethodGet, "/prove/transfer_confidential_2_2/status?jobId=x", "proving_key_not_served"},
	} {
		for _, prefix := range []string{"", gatewayPrefix} {
			response := serve(mux, test.method, prefix+test.path, transferRequest(t))
			if response.Code != http.StatusNotFound || errorCode(t, response) != test.code {
				t.Errorf("%s %s%s: got %d %q, want %s", test.method, prefix, test.path, response.Code, response.Body.String(), test.code)
			}
		}
	}
}

func TestKeyPathsReachTheirHandlers(t *testing.T) {
	mux := proofMux(t, nil)
	for _, prefix := range []string{"", gatewayPrefix} {
		// The status handler validates the job id before any lookup.
		response := serve(mux, http.MethodGet, prefix+"/prove/merge_24_1/status?jobId=x", nil)
		if response.Code != http.StatusBadRequest || errorCode(t, response) != "invalid_job_id" {
			t.Fatalf("%s status: got %d %q", prefix, response.Code, response.Body.String())
		}
		// No indexer is configured, so reaching the indexed handler is a 404
		// that names it.
		response = post(mux, prefix+"/prove/transfer_confidential_2_2/indexed", indexedTransferRequest(t))
		if response.Code != http.StatusNotFound || errorCode(t, response) != "indexer_unconfigured" {
			t.Fatalf("%s indexed: got %d %q", prefix, response.Code, response.Body.String())
		}
	}
}

// Every proof names its key: there is no path that takes any key.
func TestThereIsNoPathWithoutAKey(t *testing.T) {
	mux := proofMux(t, nil)
	for _, prefix := range []string{"", gatewayPrefix} {
		if response := post(mux, prefix+"/prove", transferRequest(t)); response.Code != http.StatusNotFound {
			t.Errorf("%s/prove: got %d", prefix, response.Code)
		}
		for _, test := range []struct{ method, path string }{
			{http.MethodPost, "/prove/indexed"},
			{http.MethodGet, "/prove/status?jobId=x"},
		} {
			response := serve(mux, test.method, prefix+test.path, transferRequest(t))
			if response.Code != http.StatusNotFound || errorCode(t, response) != "unknown_proving_key" {
				t.Errorf("%s %s%s: got %d %q", test.method, prefix, test.path, response.Code, response.Body.String())
			}
		}
	}
}

// A queued job keeps the key its path named, because the worker, not the
// handler, decodes the body far enough to know its key.
func TestQueuedJobIsHeldToItsPathKey(t *testing.T) {
	_, queue := newTestQueue(t)
	readiness := NewReadiness()
	readiness.MarkReady()
	handler := proveHandler{readiness: readiness, redisQueue: queue, enableQueue: true, provingKey: "transfer_confidential_1_2.key"}
	response := httptest.NewRecorder()
	handler.handleAsyncProof(response, httptest.NewRequest(http.MethodPost, "/prove/transfer_confidential_1_2", nil), transferRequest(t), common.ProofRequestMeta{CircuitType: common.TransferConfidentialCircuitType})
	if response.Code != http.StatusAccepted {
		t.Fatalf("enqueue got %d %q", response.Code, response.Body.String())
	}
	var queued struct{ JobID, StatusURL string }
	if err := json.Unmarshal(response.Body.Bytes(), &queued); err != nil {
		t.Fatal(err)
	}
	if queued.StatusURL != "/prove/transfer_confidential_1_2/status?jobId="+queued.JobID {
		t.Fatalf("status url %q", queued.StatusURL)
	}
	job, err := queue.DequeueProof("zk_transfer_queue", 0)
	if err != nil || job == nil {
		t.Fatalf("dequeue: %v", err)
	}
	if job.ProvingKey != "transfer_confidential_1_2.key" {
		t.Fatalf("queued job key %q", job.ProvingKey)
	}

	worker := NewTransferQueueWorker(WorkerConfig{Queue: queue, Keys: common.NewLazyKeyManager(t.TempDir(), &common.DownloadConfig{}), Ready: readyNow()}, NewExecution(1))
	_, err = worker.generatePreparedProof(&indexed.Resolved{Payload: job.Payload}, job.ProvingKey)
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != "proving_key_mismatch" {
		t.Fatalf("worker proved a 2x2 body queued on the 1x2 path: %v", err)
	}
}

func TestHealthListsTheCircuitsOfServedKeys(t *testing.T) {
	if got := servedCircuits(servedKeys(t, "merge_*", "custom_ring_base")); !slices.Equal(got, []common.CircuitType{
		common.MergeCircuitType,
		common.MergeRingCircuitType,
		common.CustomRingBaseCircuitType,
	}) {
		t.Fatalf("served circuits %v", got)
	}
	if got := servedCircuits(nil); !slices.Equal(got, allCircuits()) {
		t.Fatalf("every key serves %v", got)
	}
}

// The result and failure caches are keyed by the input hash, so a refusal on
// one key's path must not be replayed when the same body goes to its own key's
// path, nor a proof cached there served on another key's path.
func TestInputHashSeparatesKeyPaths(t *testing.T) {
	body := transferRequest(t)
	hashes := map[string]bool{}
	for _, key := range []string{"", "transfer_confidential_1_2.key", "transfer_confidential_2_2.key"} {
		hashes[ComputeInputHash(body, key)] = true
	}
	if len(hashes) != 3 {
		t.Fatalf("one body hashed alike on different key paths: %v", hashes)
	}
}
