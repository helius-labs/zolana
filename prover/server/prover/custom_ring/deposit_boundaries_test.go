package custom_ring

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"zolana/prover/custom_rings/circuits/deposit"
	"zolana/prover/prover-test/spp/spptest"
)

func TestDepositCircuitRejectsOutOfRangeCountsWithMatchingPublicHash(t *testing.T) {
	for _, row := range []struct {
		name    string
		valid   uint32
		invalid uint32
	}{
		{name: "empty batch", valid: 1, invalid: 0},
		{name: "oversized batch", valid: deposit.MaxDeposits, invalid: deposit.MaxDeposits + 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			vector, _ := depositFixture(t, row.valid)
			assignment, err := vector.Params.CreateWitness()
			if err != nil {
				t.Fatal(err)
			}
			if err := test.IsSolved(&deposit.CustomRingDepositCircuit{}, assignment, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("valid boundary control failed: %v", err)
			}

			// Zero padding isolates rejection of invalid counts.
			vector.Params.Count = 0
			for i := range vector.Params.OwnerPkHashes {
				vector.Params.OwnerPkHashes[i], vector.Params.NullifierPks[i], vector.Params.Blindings[i] = big.NewInt(0), big.NewInt(0), big.NewInt(0)
			}
			_, chain := encryptDepositVector(t, vector.Params)
			chain[2] = new(big.Int).SetUint64(uint64(row.invalid))
			vector.Params.PublicInputHash = spptest.MustHashChain(t, chain)
			assignment.Count = row.invalid
			assignment.PublicInputHash = vector.Params.PublicInputHash
			for i := range assignment.OwnerPkHashes {
				assignment.OwnerPkHashes[i], assignment.NullifierPks[i], assignment.Blindings[i] = vector.Params.OwnerPkHashes[i], vector.Params.NullifierPks[i], vector.Params.Blindings[i]
			}
			if err := test.IsSolved(&deposit.CustomRingDepositCircuit{}, assignment, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("circuit accepted a count outside its occupied prefix")
			}
		})
	}
}
