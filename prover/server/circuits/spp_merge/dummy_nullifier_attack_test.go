package merge_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	merge "zolana/prover/circuits/spp_merge"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
	"zolana/prover/prover-test/poseidon"
)

// Regression tests for INV-MERGE-16 (pre-PR164): the old spp_merge circuit left
// a dummy slot's published nullifier a free witness -- the derived-nullifier
// binding was gated on notDummy and distinctness on both-real -- so a merge
// delegate could park a victim's real nullifier in a padding slot. The program
// queues every slot's nullifier: the victim's UTXO is burned without its value
// entering the merged output, and an unprovable queued value halts the
// strictly-ordered nullifier queue. Post-PR164 a dummy slot's nullifier is
// derived deterministically in-circuit via
// MergeDummyNullifier(nullifierSecret, firstNullifier, slotIndex) and bound
// to the published signal (shared/inputs.go), and distinctness covers
// real and dummy slots alike.

// refreshDefaultPublicInputHash recomputes the default-rail public input hash
// from the fixture's current public columns, so a mutated witness fails only on
// the constraint under test, not the hash binding.
func refreshDefaultPublicInputHash(t *testing.T, f *mergeWitnessFixture) {
	t.Helper()
	asBigInts := func(vs []frontend.Variable) []*big.Int {
		out := make([]*big.Int, len(vs))
		for i, v := range vs {
			out[i] = v.(*big.Int)
		}
		return out
	}
	f.publicInputHash = hashChain(t, []*big.Int{
		hashChain(t, asBigInts(f.public.Nullifiers)),
		f.public.OutputHash.(*big.Int),
		hashChain(t, asBigInts(f.public.UtxoTreeRoots)),
		hashChain(t, asBigInts(f.public.NullifierTreeRoots)),
		f.public.PrivateTxHash.(*big.Int),
		f.public.ExternalDataHash.(*big.Int),
		f.public.AllowDummyInputs.(*big.Int),
		f.userSigningPkHash,
	})
}

// TestMergeRejectsVictimNullifierInDummySlot (INV-MERGE-16): publishing the first real
// input's genuine nullifier in dummy slot 2 -- the delegate burning that UTXO by
// queuing its nullifier without merging its value -- must not solve, even with a
// consistent public input hash. The in-circuit nullifier for a dummy slot is
// MergeDummyNullifier(nullifierSecret, firstNullifier, 2); the binding to the
// published signal is the sole rejecting constraint (distinctness runs over the
// unchanged, still-distinct in-circuit nullifiers). Pre-PR164 this witness
// solved.
func TestMergeRejectsVictimNullifierInDummySlot(t *testing.T) {
	assert := test.NewAssert(t)
	fixture := buildMergeFixture(t, mergeFixtureOptions{})
	victimNullifier := fixture.public.Nullifiers[0]
	fixture.public.Nullifiers[2] = victimNullifier
	refreshDefaultPublicInputHash(t, fixture)

	assert.SolvingFailed(merge.NewMergeCircuit(), fixture.defaultCircuit(), test.WithCurves(ecc.BN254))
}

// TestMergeAcceptsDerivedDummyNullifiers is the positive control: the fixture
// publishes exactly MergeDummyNullifier(nullifierSecret, firstNullifier, slot)
// in every dummy slot, and that witness solves. It also pins the host-side
// derivation against the circuit's domain and argument order, so the negative
// test above cannot pass for a broken-baseline reason.
func TestMergeAcceptsDerivedDummyNullifiers(t *testing.T) {
	assert := test.NewAssert(t)
	fixture := buildMergeFixture(t, mergeFixtureOptions{})

	nullifierSecret := fixture.userNullifierSecret
	firstNullifier := fixture.public.Nullifiers[0].(*big.Int)
	for slot := 2; slot < merge.MergeInputs; slot++ {
		want, err := poseidon.Hash([]*big.Int{
			big.NewInt(mergeshared.MergeDummyNullifierDomain),
			nullifierSecret,
			firstNullifier,
			big.NewInt(int64(slot)),
		})
		if err != nil {
			t.Fatal(err)
		}
		got := fixture.public.Nullifiers[slot].(*big.Int)
		if got.Cmp(want) != 0 {
			t.Fatalf("dummy slot %d nullifier: got %x want derived %x", slot, got, want)
		}
	}

	assert.SolvingSucceeded(merge.NewMergeCircuit(), fixture.defaultCircuit(), test.WithCurves(ecc.BN254))
}
