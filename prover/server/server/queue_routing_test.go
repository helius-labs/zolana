package server

import (
	"testing"
	"zolana/prover/prover/common"
)

// Only public proof-artifact circuits are queueable. Raw transfer/merge
// witnesses contain wallet secrets and must never be persisted in Redis.
func TestGetQueueNameForCircuit(t *testing.T) {
	cases := []struct {
		circuit common.CircuitType
		queue   string
	}{
		{common.BatchAddressAppendCircuitType, "zk_address_append_queue"},
		{common.AggregateCircuitType, "zk_transfer_queue"},
		{common.NullifierFoldCircuitType, "zk_transfer_queue"},
		{common.MergeChainCircuitType, "zk_transfer_queue"},
		{common.TransferConfidentialCircuitType, ""},
		{common.TransferRingCircuitType, ""},
		{common.TransferP256RingCircuitType, ""},
		{common.TransferRingAuthorityCircuitType, ""},
		{common.MergeCircuitType, ""},
		{common.MergeRingCircuitType, ""},
		{common.CircuitType("unknown"), ""},
	}
	for _, c := range cases {
		if got := GetQueueNameForCircuit(c.circuit); got != c.queue {
			t.Errorf("GetQueueNameForCircuit(%s) = %q, want %q", c.circuit, got, c.queue)
		}
	}
}
