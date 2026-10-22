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
		{common.CircuitType("custom-ring-audit-packed-2"), "zk_custom_ring_queue"},
		{common.CircuitType("custom-ring-policy-member-2"), "zk_custom_ring_queue"},
		{common.CircuitType("custom-ring-policy-delegate-2x2"), "zk_custom_ring_queue"},
		{common.CustomRingKeyRegisterCircuitType, "zk_custom_ring_queue"},
		{common.CustomRingDepositCircuitType, "zk_custom_ring_queue"},
		{common.CircuitType("custom-ring-apply-records-16"), "zk_custom_ring_queue"},
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
	if _, err := worker.generatePreparedProof(&indexed.Resolved{Payload: json.RawMessage(`{"circuitType":"transfer"}`)}, ""); err == nil {
		t.Fatal("custom ring worker accepted a transfer proof")
	}
}

func TestCustomRingFailureDetailsDoNotContainWitnessData(t *testing.T) {
	const marker = "private-witness-marker"
	job := &ProofJob{Payload: json.RawMessage(`{"circuitType":"custom-ring-audit-packed-2","txViewingSk":"` + marker + `"}`)}

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
		common.CircuitType("custom-ring-audit-packed-2"),
		common.CircuitType("custom-ring-policy-member-2"),
		common.CircuitType("custom-ring-policy-delegate-2x2"),
		common.CustomRingKeyRegisterCircuitType,
		common.CustomRingDepositCircuitType,
		common.CircuitType("custom-ring-apply-records-16"),
	} {
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
