package merge_test

import (
	"fmt"
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
//
// The derivation's security does not depend on the slot count, and these tests
// run over every supported count to keep that true as shapes are added. Two
// facts carry the argument. The slot index is a compile-time constant, baked
// into the constraint system rather than taken from the witness, so a prover has
// no freedom in a dummy slot's nullifier whatever the width. And distinctness is
// enforced over all slots, so a collision is rejected by a constraint rather
// than assumed away. Widening only adds more slots of the same form.
//
// The costly R1CS-backed assertions run at the smallest supported count; the
// wider counts use the test engine, which evaluates the same constraints without
// paying a full compile per run.

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

// derivedDummyNullifier mirrors the in-circuit MergeDummyNullifier off-circuit.
func derivedDummyNullifier(t *testing.T, secret, firstNullifier *big.Int, slot int) *big.Int {
	t.Helper()
	nf, err := poseidon.Hash([]*big.Int{
		big.NewInt(mergeshared.MergeDummyNullifierDomain),
		secret,
		firstNullifier,
		big.NewInt(int64(slot)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return nf
}

func supportedCountSubtests(t *testing.T, run func(t *testing.T, numInputs int)) {
	t.Helper()
	for _, numInputs := range mergeshared.SupportedInputCounts {
		t.Run(fmt.Sprintf("%d_inputs", numInputs), func(t *testing.T) {
			run(t, numInputs)
		})
	}
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
	supportedCountSubtests(t, func(t *testing.T, numInputs int) {
		fixture := buildMergeFixture(t, mergeFixtureOptions{numInputs: numInputs})
		fixture.public.Nullifiers[2] = fixture.public.Nullifiers[0]
		refreshDefaultPublicInputHash(t, fixture)

		if numInputs == defaultFixtureInputs {
			test.NewAssert(t).SolvingFailed(
				merge.NewMergeCircuit(numInputs),
				fixture.defaultCircuit(),
				test.WithCurves(ecc.BN254),
			)
			return
		}
		if err := test.IsSolved(
			merge.NewMergeCircuit(numInputs),
			fixture.defaultCircuit(),
			ecc.BN254.ScalarField(),
		); err == nil {
			t.Fatal("expected dummy-nullifier binding to reject the victim nullifier, got solved")
		}
	})
}

// TestMergeRejectsDummyNullifierFromAnotherSlot pins the slot index into the
// derivation: swapping two dummy slots' published nullifiers keeps them
// pairwise distinct and keeps the public input hash consistent, so only the
// per-slot binding can reject it. The last slot is used because it is the one a
// wider shape adds.
func TestMergeRejectsDummyNullifierFromAnotherSlot(t *testing.T) {
	supportedCountSubtests(t, func(t *testing.T, numInputs int) {
		fixture := buildMergeFixture(t, mergeFixtureOptions{numInputs: numInputs})
		last := numInputs - 1
		fixture.public.Nullifiers[2], fixture.public.Nullifiers[last] =
			fixture.public.Nullifiers[last], fixture.public.Nullifiers[2]
		refreshDefaultPublicInputHash(t, fixture)

		if err := test.IsSolved(
			merge.NewMergeCircuit(numInputs),
			fixture.defaultCircuit(),
			ecc.BN254.ScalarField(),
		); err == nil {
			t.Fatal("expected the slot index to bind the dummy nullifier, got solved")
		}
	})
}

// TestMergeAcceptsDerivedDummyNullifiers is the positive control: the fixture
// publishes exactly MergeDummyNullifier(nullifierSecret, firstNullifier, slot)
// in every dummy slot, and that witness solves. It also pins the host-side
// derivation against the circuit's domain and argument order, so the negative
// tests above cannot pass for a broken-baseline reason.
func TestMergeAcceptsDerivedDummyNullifiers(t *testing.T) {
	supportedCountSubtests(t, func(t *testing.T, numInputs int) {
		fixture := buildMergeFixture(t, mergeFixtureOptions{numInputs: numInputs})
		firstNullifier := fixture.public.Nullifiers[0].(*big.Int)
		for slot := 2; slot < numInputs; slot++ {
			want := derivedDummyNullifier(t, fixture.userNullifierSecret, firstNullifier, slot)
			got := fixture.public.Nullifiers[slot].(*big.Int)
			if got.Cmp(want) != 0 {
				t.Fatalf("dummy slot %d nullifier: got %x want derived %x", slot, got, want)
			}
		}

		if numInputs == defaultFixtureInputs {
			test.NewAssert(t).SolvingSucceeded(
				merge.NewMergeCircuit(numInputs),
				fixture.defaultCircuit(),
				test.WithCurves(ecc.BN254),
			)
			return
		}
		if err := test.IsSolved(
			merge.NewMergeCircuit(numInputs),
			fixture.defaultCircuit(),
			ecc.BN254.ScalarField(),
		); err != nil {
			t.Fatalf("derived dummy nullifiers not solved at %d inputs: %v", numInputs, err)
		}
	})
}

// TestMergeDummyNullifiersStayDistinctAcrossTheWidestShape checks the published
// nullifier set is collision-free at every supported width. The circuit rejects
// a collision rather than tolerating one, so a forced collision would make the
// widest shape unprovable; this fails loudly instead of surfacing as an
// unsatisfiable witness in the field.
func TestMergeDummyNullifiersStayDistinctAcrossTheWidestShape(t *testing.T) {
	supportedCountSubtests(t, func(t *testing.T, numInputs int) {
		fixture := buildMergeFixture(t, mergeFixtureOptions{numInputs: numInputs})
		seen := make(map[string]int, numInputs)
		for slot := 0; slot < numInputs; slot++ {
			value := fixture.public.Nullifiers[slot].(*big.Int)
			key := value.Text(16)
			if previous, duplicate := seen[key]; duplicate {
				t.Fatalf("slots %d and %d publish the same nullifier %s", previous, slot, key)
			}
			seen[key] = slot
		}
	})
}

// TestMergeDummyNullifiersDependOnTheFirstNullifier pins the other half of the
// derivation's seed. Dummy values are reused verbatim across shapes for the same
// slot index, so what keeps two merges from publishing the same padding
// nullifier is that nullifiers[0] is single-use: the program queues it, and the
// next merge's slot zero cannot prove non-inclusion for it. This asserts the
// dependence the argument rests on.
func TestMergeDummyNullifiersDependOnTheFirstNullifier(t *testing.T) {
	secret := big.NewInt(19)
	firstA := big.NewInt(0xA1)
	firstB := big.NewInt(0xB2)
	for _, numInputs := range mergeshared.SupportedInputCounts {
		for slot := 1; slot < numInputs; slot++ {
			a := derivedDummyNullifier(t, secret, firstA, slot)
			b := derivedDummyNullifier(t, secret, firstB, slot)
			if a.Cmp(b) == 0 {
				t.Fatalf("slot %d dummy nullifier is independent of nullifiers[0]", slot)
			}
		}
	}
}
