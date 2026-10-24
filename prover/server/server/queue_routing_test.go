package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	"github.com/helius-labs/zolana/prover/server/prover/indexed"
	"strings"
	"testing"
)

// Transfer/merge circuits share zk_transfer_queue; address-append keeps its own;
// everything else is not queued (empty name).
func TestGetQueueNameForCircuit(t *testing.T) {
	cases := []struct {
		circuit common.CircuitType
		queue   string
	}{
		{common.BatchAddressAppendCircuitType, "zk_address_append_queue"},
		{common.TransferConfidentialCircuitType, "zk_transfer_queue"},
		{common.TransferRingCircuitType, "zk_transfer_queue"},
		{common.TransferAnonymousRingEddsaCircuitType, "zk_transfer_queue"},
		{common.TransferRingAuthorityCircuitType, "zk_transfer_queue"},
		{common.MergeCircuitType, "zk_transfer_queue"},
		{common.MergeRingCircuitType, "zk_transfer_queue"},
		{testExtension, extensionQueue},
		{common.CircuitType("unknown"), ""},
	}
	for _, c := range cases {
		if got := GetQueueNameForCircuit(c.circuit); got != c.queue {
			t.Errorf("GetQueueNameForCircuit(%s) = %q, want %q", c.circuit, got, c.queue)
		}
	}
}

func TestExtensionWorkerRejectsOtherCircuits(t *testing.T) {
	worker := &BaseQueueWorker{queueName: extensionQueue}
	if _, err := worker.generatePreparedProof(&indexed.Resolved{Payload: json.RawMessage(`{"circuitType":"transfer"}`)}, ""); err == nil {
		t.Fatal("extension worker accepted a transfer proof")
	}
}

func TestExtensionFailureDetailsDoNotContainWitnessData(t *testing.T) {
	const marker = "private-witness-marker"
	job := &ProofJob{Payload: json.RawMessage(`{"circuitType":"test-extension","x":"` + marker + `"}`)}

	worker := &BaseQueueWorker{queueName: extensionQueue}
	details := worker.failureDetails(job, errors.New(marker))
	encoded := fmt.Sprint(details)
	if strings.Contains(encoded, marker) {
		t.Fatal("failure details contain witness data")
	}
}

func TestExtensionCachedFailureDoesNotContainWitnessData(t *testing.T) {
	const marker = "cached-private-witness-marker"
	worker := &BaseQueueWorker{queueName: extensionQueue}

	message := worker.cachedFailureMessage(map[string]interface{}{"error": marker})
	if strings.Contains(message, marker) {
		t.Fatal("cached failure contains witness data")
	}
}

func TestExtensionIsServedOnEveryRail(t *testing.T) {
	for _, want := range []common.CircuitType{testExtension} {
		if (proveHandler{}).shouldUseQueueForCircuit(want) {
			t.Fatalf("%s routed to a queue the server does not have", want)
		}
		queued := proveHandler{enableQueue: true, redisQueue: &RedisQueue{}}
		if !queued.shouldUseQueueForCircuit(want) {
			t.Fatalf("%s skipped the queue the server has", want)
		}
		found := false
		for _, circuit := range servedCircuits(nil) {
			if circuit == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s missing from the served circuits", want)
		}
	}
}
