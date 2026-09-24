package main

import (
	"reflect"
	"strconv"
	"testing"

	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/server"
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

// A forester deployment still passes `--circuit address-append`; the image
// has to start on that flag line and serve the forester route.
func TestStartRoutesAcceptsTheDeprecatedCircuitFlag(t *testing.T) {
	for _, tc := range []struct {
		routes, circuits []string
		want             []server.ProofRoute
	}{
		{nil, nil, server.AllProofRoutes},
		{[]string{"merge"}, nil, []server.ProofRoute{server.MergeRoute}},
		{nil, []string{"address-append"}, []server.ProofRoute{server.ForesterRoute}},
		{nil, []string{"address-append", "address-append-test"}, []server.ProofRoute{server.ForesterRoute}},
		{nil, []string{"transfer", "custom-ring-base"}, []server.ProofRoute{server.SppRoute, server.CustomRingRoute}},
	} {
		got, err := startRoutes(tc.routes, tc.circuits)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("startRoutes(%v, %v) = %v, %v; want %v", tc.routes, tc.circuits, got, err, tc.want)
		}
	}

	for _, tc := range []struct{ routes, circuits []string }{
		{[]string{"spp"}, []string{"address-append"}},
		{nil, []string{"not-a-circuit"}},
	} {
		if _, err := startRoutes(tc.routes, tc.circuits); err == nil {
			t.Errorf("startRoutes(%v, %v) accepted an invalid flag line", tc.routes, tc.circuits)
		}
	}
}
