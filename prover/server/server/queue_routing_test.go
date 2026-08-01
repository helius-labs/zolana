package server

import (
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
		{common.CircuitType("unknown"), ""},
	}
	for _, c := range cases {
		if got := GetQueueNameForCircuit(c.circuit); got != c.queue {
			t.Errorf("GetQueueNameForCircuit(%s) = %q, want %q", c.circuit, got, c.queue)
		}
	}
}
