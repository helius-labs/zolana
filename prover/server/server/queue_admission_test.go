package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	nullifiertreetest "github.com/helius-labs/zolana/prover/server/prover-test/nullifier_tree"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func queueingHandler(t *testing.T, queue *RedisQueue) proveHandler {
	t.Helper()
	readiness := NewReadiness()
	readiness.MarkReady()
	return proveHandler{readiness: readiness, redisQueue: queue, enableQueue: true}
}

func submitAsync(handler proveHandler, body []byte, circuit common.CircuitType) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.handleAsyncProof(response, httptest.NewRequest(http.MethodPost, "/prove", nil), body, common.ProofRequestMeta{CircuitType: circuit})
	return response
}

// A body a worker would refuse is refused before it writes anything to Redis:
// a body that names a circuit and omits its values used to leave a job, its
// metadata and a failure index entry behind.
func TestAsyncRefusesAnIncompleteBodyBeforeRedis(t *testing.T) {
	redis, queue := newTestQueue(t)
	handler := queueingHandler(t, queue)
	for name, submission := range map[string]struct {
		body    string
		circuit common.CircuitType
	}{
		"transfer without values":        {string(transferRequest(t)), common.TransferConfidentialCircuitType},
		"bare transfer":                  {`{"circuitType":"transfer-confidential","nInputs":2,"nOutputs":2}`, common.TransferConfidentialCircuitType},
		"transfer shape without a key":   {`{"circuitType":"transfer-confidential","nInputs":7,"nOutputs":7}`, common.TransferConfidentialCircuitType},
		"bare anonymous ring transfer":   {`{"circuitType":"transfer-eddsa-ring","nInputs":2,"nOutputs":2}`, common.TransferAnonymousRingEddsaCircuitType},
		"bare address append":            {`{"circuitType":"address-append","treeHeight":40,"batchSize":10}`, common.BatchAddressAppendCircuitType},
		"address append without a key":   {`{"circuitType":"address-append","treeHeight":40,"batchSize":11}`, common.BatchAddressAppendCircuitType},
		"extension that does not decode": {`{"circuitType":"test-extension","x":"three"}`, testExtension},
	} {
		response := submitAsync(handler, []byte(submission.body), submission.circuit)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s: got %d %q", name, response.Code, response.Body.String())
		}
		if keys := redis.Keys(); len(keys) != 0 {
			t.Fatalf("%s: a refused body left Redis state: %v", name, keys)
		}
	}
}

// The queue dedupes what a request proves, not its bytes: a field the circuit
// does not read, or another layout of the same values, is the same job.
func TestAsyncDeduplicatesTheDecodedRequest(t *testing.T) {
	_, queue := newTestQueue(t)
	handler := queueingHandler(t, queue)
	body := validTransferRequest(t)
	var object map[string]any
	if err := json.Unmarshal(body, &object); err != nil {
		t.Fatal(err)
	}
	object["padding"] = "first"
	padded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	indented := bytes.Replace(body, []byte(`"nInputs":2`), []byte(`"padding":"second", "nInputs":  2`), 1)
	if bytes.Equal(indented, body) {
		t.Fatal("fixture lacks nInputs")
	}

	var jobs []string
	for _, submission := range [][]byte{body, padded, indented} {
		response := submitAsync(handler, submission, common.TransferConfidentialCircuitType)
		if response.Code != http.StatusAccepted {
			t.Fatalf("got %d %q", response.Code, response.Body.String())
		}
		var queued struct{ JobID string }
		if err := json.Unmarshal(response.Body.Bytes(), &queued); err != nil {
			t.Fatal(err)
		}
		jobs = append(jobs, queued.JobID)
	}
	if jobs[0] != jobs[1] || jobs[0] != jobs[2] {
		t.Fatalf("one request queued as several jobs: %v", jobs)
	}
	job, err := queue.DequeueProof("zk_transfer_queue", 0)
	if err != nil || job == nil {
		t.Fatalf("dequeue: %v", err)
	}
	if strings.Contains(string(job.Payload), "padding") {
		t.Fatal("the queued job kept a field the circuit does not read")
	}
}

// witnessBytes is the full witness a body proves.
func witnessBytes(t *testing.T, circuit common.CircuitType, payload []byte) []byte {
	t.Helper()
	request, failure := circuitProver{}.admit(circuit, payload)
	if failure != nil {
		t.Fatalf("%s: %v", circuit, failure)
	}
	assignment, err := request.witness()
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := witness.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// What the queue stores proves exactly what the submitter sent, so the worker
// proves the same statement the handler admitted.
func TestQueuedEncodingProvesTheSubmittedRequest(t *testing.T) {
	batch, err := nullifiertreetest.BuildTestAddressTree(40, 10, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	batchBody, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		name    string
		body    []byte
		circuit common.CircuitType
	}{
		{"address append", batchBody, common.BatchAddressAppendCircuitType},
		{"extension", validExtensionPayload, testExtension},
	}
	for _, fixture := range []struct {
		path    string
		circuit common.CircuitType
	}{
		{"../prover/request/testdata/transfer-2x2.json", common.TransferConfidentialCircuitType},
		{"../prover/transfer_eddsa/testdata/eddsa-ring-2x2.json", common.TransferAnonymousRingEddsaCircuitType},
		{"../prover/transfer_eddsa/testdata/confidential-eddsa-2x8.json", common.TransferConfidentialEddsaCircuitType},
	} {
		body, err := os.ReadFile(fixture.path)
		if err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, struct {
			name    string
			body    []byte
			circuit common.CircuitType
		}{fixture.path, body, fixture.circuit})
	}
	for _, fixture := range fixtures {
		queued, failure := circuitProver{}.validateQueued(fixture.circuit, fixture.body)
		if failure != nil {
			t.Fatalf("%s: %v", fixture.name, failure)
		}
		if !bytes.Equal(witnessBytes(t, fixture.circuit, queued), witnessBytes(t, fixture.circuit, fixture.body)) {
			t.Fatalf("%s: the queued encoding proves another witness", fixture.name)
		}
		meta, err := common.ParseProofRequestMeta(queued)
		if err != nil || meta.CircuitType != fixture.circuit {
			t.Fatalf("%s: the worker reads circuit %q from the queued encoding: %v", fixture.name, meta.CircuitType, err)
		}
	}
}

func TestAsyncRefusesAFullQueue(t *testing.T) {
	redis, queue := newTestQueue(t)
	handler := queueingHandler(t, queue)
	handler.maxPending = 1
	if err := queue.EnqueueProof("zk_transfer_queue", testJob("waiting")); err != nil {
		t.Fatal(err)
	}
	before := redis.Keys()
	response := submitAsync(handler, validTransferRequest(t), common.TransferConfidentialCircuitType)
	if response.Code != http.StatusServiceUnavailable || errorCode(t, response) != "queue_full" || response.Header().Get("Retry-After") == "" {
		t.Fatalf("got %d %q", response.Code, response.Body.String())
	}
	if after := redis.Keys(); len(after) != len(before) {
		t.Fatalf("a refused submission left Redis state: %v", after)
	}

	// Tree sub-queues count toward their queue.
	tree := testJob("tree")
	tree.TreeID = "tree"
	if err := queue.EnqueueProof("zk_address_append_queue", tree); err != nil {
		t.Fatal(err)
	}
	if failure := queue.admitPending("zk_address_append_queue", 1); failure == nil {
		t.Fatal("a full fair queue admitted a submission")
	}
	if failure := queue.admitPending("zk_address_append_queue", 0); failure != nil {
		t.Fatal("an unbounded queue refused a submission")
	}
}

// A failed job deletes the mapping from its id to its input hash, which
// cleanup used to need to find its failure index entry, so the entry stayed
// forever. Cleanup now drops every entry whose job left the queue.
func TestCleanupPrunesIndexEntriesWithoutJobs(t *testing.T) {
	_, queue := newTestQueue(t)
	old := &ProofJob{ID: "old_failed", Type: "failed", Payload: json.RawMessage(`{}`), CreatedAt: time.Now().Add(-2 * time.Hour)}
	live := &ProofJob{ID: "live_failed", Type: "failed", Payload: json.RawMessage(`{}`), CreatedAt: time.Now()}
	for _, job := range []*ProofJob{old, live} {
		if err := queue.EnqueueProof("zk_failed_queue", job); err != nil {
			t.Fatal(err)
		}
	}
	for hash, job := range map[string]string{"old-hash": "old", "live-hash": "live", "orphan-hash": "orphan"} {
		if err := queue.IndexFailureByHash(hash, job); err != nil {
			t.Fatal(err)
		}
	}
	result := &ProofJob{ID: "kept", Type: "result", Payload: json.RawMessage(`{}`), CreatedAt: time.Now()}
	if err := queue.EnqueueProof("zk_results_queue", result); err != nil {
		t.Fatal(err)
	}
	for hash, job := range map[string]string{"kept-hash": "kept", "gone-hash": "gone"} {
		if err := queue.IndexResultByHash(hash, job); err != nil {
			t.Fatal(err)
		}
	}

	if err := queue.CleanupOldFailedJobs(); err != nil {
		t.Fatal(err)
	}
	if err := queue.CleanupOldResults(); err != nil {
		t.Fatal(err)
	}
	failed, err := queue.Client.HGetAll(queue.Ctx, FailedIndexKey).Result()
	if err != nil || len(failed) != 1 || failed["live-hash"] != "live" {
		t.Fatalf("failure index %v: %v", failed, err)
	}
	results, err := queue.Client.HGetAll(queue.Ctx, ResultsIndexKey).Result()
	if err != nil || len(results) != 1 || results["kept-hash"] != "kept" {
		t.Fatalf("results index %v: %v", results, err)
	}
}
