package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"zolana/prover/prover/common"
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
		{common.TransferP256RingCircuitType, "zk_transfer_queue"},
		{common.TransferRingAuthorityCircuitType, "zk_transfer_queue"},
		{common.MergeCircuitType, "zk_transfer_queue"},
		{common.MergeRingCircuitType, "zk_transfer_queue"},
		{common.CustomRingBaseCircuitType, "zk_custom_ring_queue"},
		{common.CustomRingPolicyCircuitType, "zk_custom_ring_queue"},
		{common.CircuitType("unknown"), ""},
	}
	for _, c := range cases {
		if got := GetQueueNameForCircuit(c.circuit); got != c.queue {
			t.Errorf("GetQueueNameForCircuit(%s) = %q, want %q", c.circuit, got, c.queue)
		}
	}
}

func TestCustomRingWorkerRejectsOtherCircuits(t *testing.T) {
	worker := &BaseQueueWorker{queueName: "zk_custom_ring_queue"}
	job := &ProofJob{Payload: json.RawMessage(`{"circuitType":"transfer"}`)}

	if _, err := worker.generateProof(job); err == nil {
		t.Fatal("custom ring worker accepted a transfer proof")
	}
}

func TestCustomRingFailureDetailsDoNotContainWitnessData(t *testing.T) {
	const marker = "private-witness-marker"
	job := &ProofJob{Payload: json.RawMessage(`{"circuitType":"custom-ring-base","txViewingSk":"` + marker + `"}`)}

	worker := &BaseQueueWorker{queueName: "zk_custom_ring_queue"}
	details := worker.failureDetails(job, errors.New(marker))
	encoded := fmt.Sprint(details)
	if strings.Contains(encoded, marker) {
		t.Fatal("failure details contain witness data")
	}
}

func TestCustomRingCachedFailureDoesNotContainWitnessData(t *testing.T) {
	const marker = "cached-private-witness-marker"
	worker := &BaseQueueWorker{queueName: "zk_custom_ring_queue"}

	message := worker.cachedFailureMessage(map[string]interface{}{"error": marker})
	if strings.Contains(message, marker) {
		t.Fatal("cached failure contains witness data")
	}
}

func TestCustomRingIsServedOnEveryRail(t *testing.T) {
	for _, want := range []common.CircuitType{
		common.CustomRingBaseCircuitType,
		common.CustomRingPolicyCircuitType,
	} {
		if (proveHandler{}).shouldUseQueueForCircuit(want) {
			t.Fatalf("%s routed to a queue the server does not have", want)
		}
		queued := proveHandler{enableQueue: true, redisQueue: &RedisQueue{}}
		if !queued.shouldUseQueueForCircuit(want) {
			t.Fatalf("%s skipped the queue the server has", want)
		}
		found := false
		for _, circuit := range servedCircuits() {
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
