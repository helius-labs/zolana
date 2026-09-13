package main

import (
	"strconv"
	"testing"

	txcircuit "zolana/prover/circuits/spp_transaction/shared"
)

func TestTransferSetupInputCount(t *testing.T) {
	for _, value := range []uint{1, 2, 3, 4, 5, 36, 60} {
		t.Run(strconv.FormatUint(uint64(value), 10), func(t *testing.T) {
			got, err := transferSetupInputCount(value)
			if err != nil || uint(got) != value {
				t.Fatalf("input count changed or rejected: got %d, err %v", got, err)
			}
			if (txcircuit.Shape{NInputs: int(got), NOutputs: 1}).SignerWidth() < 1 {
				t.Fatal("accepted count leaves no signer slot for the payer")
			}
		})
	}

	invalid := []uint{0, 61, 62, ^uint(0)}
	// On a 64-bit host, this used to truncate to one input before validation.
	wrapped := uint64(1)<<32 + 1
	if uint64(^uint(0)) >= wrapped {
		invalid = append(invalid, uint(wrapped))
	}
	for _, value := range invalid {
		t.Run(strconv.FormatUint(uint64(value), 10), func(t *testing.T) {
			got, err := transferSetupInputCount(value)
			if err == nil || got != 0 {
				t.Fatalf("invalid count accepted: got %d, err %v", got, err)
			}
		})
	}
}
