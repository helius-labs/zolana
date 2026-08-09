package server

import (
	"context"
	"testing"
)

// An unbounded synchronous path starts one Groth16 prove per request, each
// holding a proving key.
func TestSyncProofsAreBounded(t *testing.T) {
	if slots := cap(syncProofSlots()); slots < MinConcurrencyPerWorker {
		t.Fatalf("synchronous proof slots = %d, want at least %d", slots, MinConcurrencyPerWorker)
	}
}

// A cancelled request must not reach a proving key. The nil key manager panics
// if the prove starts, so the returned error is the evidence it did not.
func TestProcessProofSyncStopsForAnAbandonedRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	handler := proveHandler{}
	_, proofError := handler.processProofSync(ctx, []byte(`{"circuitType":"transfer-confidential","nInputs":2,"nOutputs":2}`))

	if proofError == nil {
		t.Fatal("expected an error for a cancelled request")
	}
	if proofError.Code != "request_abandoned" {
		t.Fatalf("expected request_abandoned, got %q", proofError.Code)
	}
}
