package server

import (
	"testing"
	"time"
	"zolana/prover/prover/common"
)

func TestSyncProofTimeout(t *testing.T) {
	handler := proveHandler{}
	cases := []struct {
		circuit common.CircuitType
		timeout time.Duration
	}{
		{common.CustomRingBaseCircuitType, 5 * time.Minute},
		{common.CustomRingPolicyCircuitType, 5 * time.Minute},
		{common.TransferP256RingCircuitType, 5 * time.Minute},
		{common.BatchAddressAppendCircuitType, time.Minute},
		{common.TransferRingCircuitType, time.Minute},
		{common.MergeRingCircuitType, 2 * time.Minute},
		{common.CircuitType("unknown"), 10 * time.Second},
	}
	for _, tc := range cases {
		t.Run(string(tc.circuit), func(t *testing.T) {
			if got := handler.syncProofTimeout(tc.circuit); got != tc.timeout {
				t.Fatalf("timeout = %s, want %s", got, tc.timeout)
			}
		})
	}
}
