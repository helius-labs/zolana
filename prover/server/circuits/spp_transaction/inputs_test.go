package transaction_test

import (
	"math/big"
	"testing"
	"zolana/prover/circuits/gadget"
	. "zolana/prover/circuits/spp_transaction"

	"zolana/prover/prover-test/poseidon"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	gnarkbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/test"
)

func TestCircuitRejectsBadStatePathElements(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].StatePathElements[0] = spptest.Fe(999)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadStatePathIndex(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].StatePathIndex = new(big.Int).Add(spptest.AsBigInt(assignment.Inputs[0].StatePathIndex), big.NewInt(1))

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadNullifierNonInclusionPath(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].NullifierLowPathElements[0] = spptest.Fe(999)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// reassignInputToFreshTrees moves input idx onto an independent state tree and an
// independent nullifier tree so the proof spans more than one root. The other
// inputs keep the roots assigned by buildCircuitAssignment, so the witness has
// distinct UtxoTreeRoot/NullifierTreeRoot values across inputs. The input's UTXO
// and nullifier are unchanged, so only the membership witnesses and roots are
// rewritten; the public input hash is refreshed since per-input roots are
// committed in it.
func reassignInputToFreshTrees(t testing.TB, assignment *Circuit, idx int) (stateRoot, nullifierRoot *big.Int) {
	t.Helper()
	if idx < 0 || idx >= len(assignment.Inputs) {
		t.Fatalf("reassign input index %d out of range", idx)
	}

	in := &assignment.Inputs[idx]
	inputHash := spptest.MustUtxoHash(t, circuitFieldsToUtxo(in.Utxo))

	const freshStateLeafIndex = 99
	stateRoot, stateProofs := spptest.MustBuildSparseStateTree(t, map[uint64]*big.Int{
		freshStateLeafIndex: inputHash,
	})
	stateProof := stateProofs[freshStateLeafIndex]
	fillStateProofElements(in.StatePathElements, stateProof.PathElements)
	in.StatePathIndex = new(big.Int).SetUint64(stateProof.PathIndex)
	in.UtxoTreeRoot = stateRoot

	nullifierTree := spptest.MustNewNullifierTree(t)
	// Insert an unrelated nullifier so this tree's root differs from the empty
	// tree the other inputs prove against; the input's own nullifier stays absent.
	if err := nullifierTree.Insert(spptest.Fe(3)); err != nil {
		t.Fatalf("perturb nullifier tree: %v", err)
	}
	nfWitness := spptest.MustNonInclusion(t, nullifierTree, spptest.AsBigInt(in.Nullifier))
	in.NullifierLowValue = nfWitness.LowValue
	in.NullifierNextValue = nfWitness.NextValue
	fillStateProofElements(in.NullifierLowPathElements, nfWitness.PathElements)
	in.NullifierLowPathIndex = new(big.Int).SetUint64(nfWitness.LowIndex)
	in.NullifierTreeRoot = nullifierTree.Root()

	refreshPublicInputHash(t, assignment)
	return stateRoot, nullifierTree.Root()
}

// Per-input roots let one transaction spend inputs from different historical
// roots. This proves two inputs against two distinct state roots and two
// distinct nullifier roots in a single proof.
func TestCircuitAcceptsInputsFromDifferentRoots(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	stateRoot, nullifierRoot := reassignInputToFreshTrees(t, assignment, 1)

	if stateRoot.Cmp(spptest.AsBigInt(assignment.Inputs[0].UtxoTreeRoot)) == 0 {
		t.Fatal("expected distinct state roots across inputs")
	}
	if nullifierRoot.Cmp(spptest.AsBigInt(assignment.Inputs[0].NullifierTreeRoot)) == 0 {
		t.Fatal("expected distinct nullifier roots across inputs")
	}

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// An input proving inclusion in one state root cannot claim a different root:
// the path no longer hashes to the claimed UtxoTreeRoot. The public input hash
// is refreshed to the wrong root so the inclusion check is the sole failure.
func TestCircuitRejectsInputClaimingWrongStateRoot(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	reassignInputToFreshTrees(t, assignment, 1)
	assignment.Inputs[1].UtxoTreeRoot = spptest.AsBigInt(assignment.Inputs[0].UtxoTreeRoot)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// An input's non-inclusion witness is checked against one nullifier root:
// claiming a different NullifierTreeRoot fails the non-inclusion check. The
// public input hash is refreshed to the wrong root so that check is the sole
// failure.
func TestCircuitRejectsInputClaimingWrongNullifierRoot(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	reassignInputToFreshTrees(t, assignment, 1)
	assignment.Inputs[1].NullifierTreeRoot = spptest.AsBigInt(assignment.Inputs[0].NullifierTreeRoot)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsProgramOwnedInput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	asset := spptest.Fe(7)
	input := sampleUtxoWithAssetAndAmount(10, asset, spptest.Fe(100))
	// A zone-owned input must be spent via zone_transact (zone PDA authorization),
	// not the default transact. The circuit pins zone fields to zero.
	input.ZoneProgramID = spptest.Fe(1)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{input},
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, asset, spptest.Fe(60)),
			sampleUtxoWithAssetAndAmount(110, asset, spptest.Fe(40)),
		},
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsSolanaOwnerKeyMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].OwnerPkHash = spptest.Fe(12345)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// The Solana-only circuit variant (no P256 gadget) proves a Solana-owned
// transaction. P256MessageHash must be 0 on this rail (no signature).
func TestSolanaCircuitSolvesSolanaInputs(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewSolanaCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.P256MessageHashLow = spptest.Fe(0)
	assignment.P256MessageHashHigh = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// Soundness guard: the Solana-only variant must reject a P256-owned input
// (input_owner_pk_hashes[i] == 0 on a real slot), since it skips the
// signature gadget. Otherwise a UTXO owned by OwnerHash(0, nullifier_pk)
// could be spent with no signature.
func TestSolanaCircuitRejectsP256Input(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewSolanaCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	assignment.P256MessageHashLow = spptest.Fe(0)
	assignment.P256MessageHashHigh = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// Spec UTXO Ownership: each input's input_owner_pk_hashes entry selects its own path
func TestCircuitAcceptsMixedP256AndSolanaInputs(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, priv, priv)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// Spec UTXO Ownership: Ed25519 owners may differ per input -- each entry binds
// its own input, each with its own nullifier secret.
func TestCircuitAcceptsDistinctSolanaOwners(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	rewriteInputAsSolanaOwner(t, assignment, 1, 0x43, spptest.Fe(777))

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// An input's entry must match the key committed in that input's owner hash:
// swapping in a sibling's (or any foreign) key fails the owner binding even
// though every entry is individually a valid pk_field.
func TestCircuitRejectsForeignSolanaOwnerEntry(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	rewriteInputAsSolanaOwner(t, assignment, 1, 0x43, spptest.Fe(777))
	assignment.Inputs[1].OwnerPkHash = testSolanaPkField(t)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// A non-zero entry binds the input's owner to the entry, never to the P256
// witness key: a P256-owned input carrying a stray non-zero entry cannot bind
// its owner.
func TestCircuitRejectsP256OwnerWithNonZeroOwnerKey(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	assignment.Inputs[0].OwnerPkHash = testSolanaPkField(t)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// buildDummyInputShield builds a valid SOL shield in the {1,2} shape whose only
// input slot is a proper dummy: a public deposit of `deposit` funds two outputs
// summing to `deposit`, with zero real inputs. It is the canonical positive
// baseline for the dummy-slot inertness constraints -- the input contributes 0
// to the balance and the transaction-hash chain -- so a negative test can flip a
// single inert field and attribute the failure to exactly that constraint.
func buildDummyInputShield(t testing.TB, deposit int64) *Circuit {
	t.Helper()
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	solAsset := protocol.SolAsset()

	// The real input amount is irrelevant: dummifying the slot zeroes it. Outputs
	// must sum to the public deposit since the dummy contributes nothing.
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(50))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(deposit))),
		big.NewInt(deposit),
		big.NewInt(0),
		spptest.Fe(0),
	)

	// Turn input[0] into an inert dummy slot: IsDummy=1 with zero amount (the
	// only pinned field). The public columns are zeroed to match the on-chain
	// zero-padded reconstruction; the remaining witness fields are gated on
	// notDummy and so are ignored.
	in := &assignment.Inputs[0]
	in.IsDummy = spptest.Fe(1)
	in.Utxo.Amount = spptest.Fe(0)
	in.Utxo.Owner = spptest.Fe(0)
	in.UtxoTreeRoot = spptest.Fe(0)
	in.NullifierTreeRoot = spptest.Fe(0)
	in.Nullifier = spptest.Fe(0)
	in.OwnerPkHash = spptest.Fe(0)

	// The dummy contributes 0 to the private-tx-hash chain, so recompute it (and
	// the derived P256 message hash) with the input hash zeroed, then refresh the
	// public-input hash from the now-canonical witness.
	OutputHashes := spptest.ToBigInts(assignment.OutputHashes())
	privateTxHash := spptest.MustPrivateTxHash(
		t,
		[]*big.Int{big.NewInt(0)},
		OutputHashes,
		noAddressHashes(1),
		spptest.AsBigInt(assignment.ExternalDataHash),
	)
	assignment.PrivateTxHash = privateTxHash
	assignment.P256MessageHashLow, assignment.P256MessageHashHigh = spptest.MustP256MessageLimbs(t, privateTxHash)
	refreshPublicInputHash(t, assignment)
	return assignment
}

// TestDummyInputSlotSolves is the positive baseline: a shield with one inert
// dummy input proves. Without it the negative tests below could pass for the
// wrong reason (an unrelated broken witness).
func TestDummyInputSlotSolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assert.SolvingSucceeded(circuit, buildDummyInputShield(t, 125), test.WithCurves(ecc.BN254))
}

// A dummy slot's public columns are unpinned so dummies can mimic real slots
// (arity hiding): a non-zero owner entry, nullifier, and roots on a dummy all
// solve once the public input hash matches. The dummy stays inert -- the
// amount pin and the notDummy gating keep it out of the balance and the
// spend checks.
func TestDummyInputAcceptsMimickedPublicColumns(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildDummyInputShield(t, 125)
	assignment.Inputs[0].OwnerPkHash = testSolanaPkField(t)
	assignment.Inputs[0].Nullifier = spptest.Fe(7)
	assignment.Inputs[0].UtxoTreeRoot = spptest.Fe(8)
	assignment.Inputs[0].NullifierTreeRoot = spptest.Fe(9)
	refreshPublicInputHash(t, assignment)
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestDummyInputRejectsNonZeroAmount pins the dummy-slot inertness constraint
// (inputs.go: AssertZeroWhen(IsDummy, Amount)). Amount is not a public
// input and the dummy's UTXO hash is selected to 0, so it does not affect the
// balance or the transcript -- flipping it isolates this single constraint as the
// sole reason the witness becomes unsatisfiable.
func TestDummyInputRejectsNonZeroAmount(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildDummyInputShield(t, 125)
	assignment.Inputs[0].Utxo.Amount = spptest.Fe(1)
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// isLessCircuit exercises the full-field comparator alone, so its constraints
// (and the alias-bits hint override below) target exactly CanonicalLimbs +
// IsLessLimbs -- the comparator behind the nullifier-ordering check in inputs.go
// (AssertStrictlyOrdered).
type isLessCircuit struct {
	A    frontend.Variable
	B    frontend.Variable
	Want frontend.Variable `gnark:",public"`
}

func (c *isLessCircuit) Define(api frontend.API) error {
	a := gadget.CanonicalLimbs(api, c.A)
	b := gadget.CanonicalLimbs(api, c.B)
	api.AssertIsEqual(gadget.IsLessLimbs(api, a, b), c.Want)
	return nil
}

func TestFullFieldCompareVectors(t *testing.T) {
	assert := test.NewAssert(t)
	pMinus1 := new(big.Int).Sub(poseidon.Modulus, big.NewInt(1))
	pMinus2 := new(big.Int).Sub(poseidon.Modulus, big.NewInt(2))
	limbSplit := new(big.Int).Lsh(big.NewInt(1), 127)

	cases := []struct {
		name string
		a, b *big.Int
		want int64
	}{
		{"small a<b", big.NewInt(1), big.NewInt(2), 1},
		{"small a>b", big.NewInt(2), big.NewInt(1), 0},
		{"equal", big.NewInt(7), big.NewInt(7), 0},
		{"zero vs max", big.NewInt(0), pMinus1, 1},
		// The case a single 2^N-offset decomposition gets wrong: a near p and
		// b small wrap a + 2^N - b past p, falsely decomposing as a < b.
		{"a near p, b small", pMinus1, big.NewInt(1), 0},
		{"adjacent at the top", pMinus2, pMinus1, 1},
		{"same hi limb, lo decides", new(big.Int).Add(limbSplit, big.NewInt(3)), new(big.Int).Add(limbSplit, big.NewInt(7)), 1},
		{"hi limb beats larger lo limb", new(big.Int).Sub(limbSplit, big.NewInt(1)), limbSplit, 1},
		{"hi limb beats larger lo limb, reversed", limbSplit, new(big.Int).Sub(limbSplit, big.NewInt(1)), 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assignment := &isLessCircuit{A: tc.a, B: tc.b, Want: big.NewInt(tc.want)}
			assert.SolvingSucceeded(&isLessCircuit{}, assignment, test.WithCurves(ecc.BN254))
		})
	}
}

// A forged "a < b" for a near p must not prove: this is the wrap-around that
// makes narrow-domain offset comparators unsound on full-field values, and in
// the nullifier tree it would be a forged non-inclusion (double spend).
func TestFullFieldCompareRejectsWrapAroundForgery(t *testing.T) {
	assert := test.NewAssert(t)
	pMinus1 := new(big.Int).Sub(poseidon.Modulus, big.NewInt(1))
	assignment := &isLessCircuit{A: pMinus1, B: big.NewInt(1), Want: big.NewInt(1)}
	assert.SolvingFailed(&isLessCircuit{}, assignment, test.WithCurves(ecc.BN254))
}

// TestFullFieldCompareRejectsAliasBits pins the canonical (< p) decomposition
// inside CanonicalLimbs: presenting the bits of x+p (the same field element
// with different limbs) must not solve. The nBits hint is overridden to emit
// the alias bits for x's decomposition only; Want is set to the verdict the
// alias limbs produce, so every other constraint is satisfied and the
// full-width ToBinary's modulus check is the sole constraint left to reject.
// If CanonicalLimbs ever drops the full-width decomposition, the alias solves
// and this assertion catches the regression.
func TestFullFieldCompareRejectsAliasBits(t *testing.T) {
	assert := test.NewAssert(t)

	// x + p must fit the 254-bit decomposition for the alias to be encodable.
	x := new(big.Int).Lsh(big.NewInt(0x9abcdef), 220)
	if new(big.Int).Add(x, poseidon.Modulus).BitLen() > 254 {
		t.Fatalf("x+p must fit 254 bits, got %d", new(big.Int).Add(x, poseidon.Modulus).BitLen())
	}
	b := new(big.Int).Add(x, big.NewInt(1))
	// Honest verdict: x < x+1 -> 1. Alias verdict: x+p > x+1 -> 0. Want the
	// alias verdict so only the modulus check can reject.
	want := big.NewInt(0)

	// nBits is GetHints()[1] (order: ithBit, nBits, nTrits). Alias only x's
	// decomposition; every other ToBinary in the circuit stays honest.
	nBitsID := solver.GetHintID(gnarkbits.GetHints()[1])
	aliasBitsHint := func(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
		v := inputs[0]
		if v.Cmp(x) == 0 {
			v = new(big.Int).Add(v, field)
		}
		for i := range outputs {
			outputs[i].SetUint64(uint64(v.Bit(i)))
		}
		return nil
	}

	assignment := &isLessCircuit{A: x, B: b, Want: want}
	assert.SolvingFailed(
		&isLessCircuit{},
		assignment,
		test.WithCurves(ecc.BN254),
		test.WithSolverOpts(solver.OverrideHint(nBitsID, aliasBitsHint)),
	)
}
