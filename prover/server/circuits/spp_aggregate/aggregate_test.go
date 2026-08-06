package spp_aggregate

import (
	"math/big"
	"testing"

	"zolana/prover/circuits/gadget"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// innerCircuit stands in for an SPP transaction circuit with one public input
// that chains the private witness and a commitment over private wires. The P256
// rail gets its commitment from emulated range checks, and the commitment makes
// the batched proof exercise the native hash-to-field path.
type innerCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	A, B            frontend.Variable
}

func (c *innerCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, []frontend.Variable{c.A, c.B}))
	commitment, err := api.(frontend.Committer).Commit(c.A)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)
	return nil
}

type innerProof struct {
	witness witness.Witness
	proof   groth16.Proof
	hash    *big.Int
}

// proveInner produces a batchable proof with the plain prover, the same call
// the shielded pool's proofs come from. No GetNativeProverOptions. The outer
// circuit takes proofs as they already are.
func proveInner(assert *test.Assert, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, a, b int64) innerProof {
	hash, err := poseidon.Hash([]*big.Int{big.NewInt(a), big.NewInt(b)})
	assert.NoError(err)

	full, err := frontend.NewWitness(&innerCircuit{PublicInputHash: hash, A: a, B: b}, ecc.BN254.ScalarField())
	assert.NoError(err)
	proof, err := groth16.Prove(ccs, pk, full)
	assert.NoError(err)
	public, err := full.Public()
	assert.NoError(err)
	assert.NoError(groth16.Verify(proof, vk, public))

	return innerProof{witness: public, proof: proof, hash: hash}
}

func innerSystem(assert *test.Assert) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &innerCircuit{})
	assert.NoError(err)
	assert.Equal(1, len(ccs.GetCommitments().CommitmentIndexes()))
	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)
	return ccs, pk, vk
}

// assignment fills a batch. aggregateHash is passed separately so a test can
// claim a chain the batch does not prove.
func assignment(assert *test.Assert, batch []innerProof, aggregateHash *big.Int) *Circuit {
	c := &Circuit{
		AggregateInputHash: aggregateHash,
		Proofs:             make([]InnerProof, len(batch)),
		Witnesses:          make([]InnerWitness, len(batch)),
	}
	for i, leg := range batch {
		p, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](leg.proof)
		assert.NoError(err)
		w, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](leg.witness)
		assert.NoError(err)
		c.Proofs[i], c.Witnesses[i] = p, w
	}
	return c
}

func chain(assert *test.Assert, batch []innerProof) *big.Int {
	acc := batch[0].hash
	for _, leg := range batch[1:] {
		next, err := poseidon.Hash([]*big.Int{acc, leg.hash})
		assert.NoError(err)
		acc = next
	}
	return acc
}

func fixedKeys(assert *test.Assert, vks ...groth16.VerifyingKey) []InnerVerifyingKey {
	fixed := make([]InnerVerifyingKey, len(vks))
	for i, vk := range vks {
		var err error
		fixed[i], err = stdgroth16.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
		assert.NoError(err)
	}
	return fixed
}

func skeleton(assert *test.Assert, n int, _ constraint.ConstraintSystem, vk groth16.VerifyingKey) *Circuit {
	vks := make([]groth16.VerifyingKey, n)
	for i := range vks {
		vks[i] = vk
	}
	c, err := NewCircuit(fixedKeys(assert, vks...))
	assert.NoError(err)
	return c
}

func TestAggregateVerifiesABatch(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	batch := []innerProof{
		proveInner(assert, ccs, pk, vk, 3, 5),
		proveInner(assert, ccs, pk, vk, 7, 11),
	}

	assert.NoError(test.IsSolved(
		skeleton(assert, len(batch), ccs, vk),
		assignment(assert, batch, chain(assert, batch)),
		ecc.BN254.ScalarField(),
	))
}

// The chain is the whole statement. A batch that claims a different one proves
// nothing about the transactions the shielded pool settled.
func TestAggregateRejectsAWrongAggregateHash(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	batch := []innerProof{
		proveInner(assert, ccs, pk, vk, 3, 5),
		proveInner(assert, ccs, pk, vk, 7, 11),
	}

	assert.Error(test.IsSolved(
		skeleton(assert, len(batch), ccs, vk),
		assignment(assert, batch, new(big.Int).Add(chain(assert, batch), big.NewInt(1))),
		ecc.BN254.ScalarField(),
	))
}

// The fold is a left fold, so order is part of the statement. Without this the
// shielded pool could settle legs in one order against a proof for another.
func TestAggregateRejectsAReorderedBatch(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	batch := []innerProof{
		proveInner(assert, ccs, pk, vk, 3, 5),
		proveInner(assert, ccs, pk, vk, 7, 11),
	}
	reordered := []innerProof{batch[1], batch[0]}

	assert.Error(test.IsSolved(
		skeleton(assert, len(batch), ccs, vk),
		assignment(assert, reordered, chain(assert, batch)),
		ecc.BN254.ScalarField(),
	))
}

// A mangled proof must fail the folded pairing check the fixed key uses.
func TestAggregateRejectsAMangledProof(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	batch := []innerProof{
		proveInner(assert, ccs, pk, vk, 3, 5),
		proveInner(assert, ccs, pk, vk, 7, 11),
	}

	mangled := assignment(assert, batch, chain(assert, batch))
	mangled.Proofs[1].Ar, mangled.Proofs[1].Krs = mangled.Proofs[1].Krs, mangled.Proofs[1].Ar

	assert.Error(test.IsSolved(
		skeleton(assert, len(batch), ccs, vk),
		mangled,
		ecc.BN254.ScalarField(),
	))
}

func TestAggregateRejectsAProofForAnotherKey(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	_, otherPk, otherVk := innerSystem(assert)

	batch := []innerProof{
		proveInner(assert, ccs, pk, vk, 3, 5),
		proveInner(assert, ccs, otherPk, otherVk, 7, 11),
	}

	assert.Error(test.IsSolved(
		skeleton(assert, len(batch), ccs, vk),
		assignment(assert, batch, chain(assert, batch)),
		ecc.BN254.ScalarField(),
	))
}

// innerCircuitAlt shares innerCircuit's witness and proof shapes and proves a
// different statement under a different key, standing in for a second batched
// kind. A leg of one kind in the other kind's slot can then only fail through
// that slot's fixed key, not through a shape mismatch.
type innerCircuitAlt struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	A, B            frontend.Variable
}

func (c *innerCircuitAlt) Define(api frontend.API) error {
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, []frontend.Variable{c.B, c.A}))
	commitment, err := api.(frontend.Committer).Commit(c.B)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)
	return nil
}

// innerCircuitPlain has no commitment, the shape of the eddsa rails and the
// swap take circuit. Mixing it with innerCircuit exercises slots whose
// commitment counts differ, the committed-beside-uncommitted case a
// P256-beside-eddsa batch hits.
type innerCircuitPlain struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	A, B            frontend.Variable
}

func (c *innerCircuitPlain) Define(api frontend.API) error {
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, []frontend.Variable{c.A, c.B}))
	return nil
}

func altSystem(assert *test.Assert) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &innerCircuitAlt{})
	assert.NoError(err)
	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)
	return ccs, pk, vk
}

func plainSystem(assert *test.Assert) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &innerCircuitPlain{})
	assert.NoError(err)
	assert.Equal(0, len(ccs.GetCommitments().CommitmentIndexes()))
	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)
	return ccs, pk, vk
}

func proveAlt(assert *test.Assert, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, a, b int64) innerProof {
	hash, err := poseidon.Hash([]*big.Int{big.NewInt(b), big.NewInt(a)})
	assert.NoError(err)

	full, err := frontend.NewWitness(&innerCircuitAlt{PublicInputHash: hash, A: a, B: b}, ecc.BN254.ScalarField())
	assert.NoError(err)
	proof, err := groth16.Prove(ccs, pk, full)
	assert.NoError(err)
	public, err := full.Public()
	assert.NoError(err)
	assert.NoError(groth16.Verify(proof, vk, public))

	return innerProof{witness: public, proof: proof, hash: hash}
}

func provePlain(assert *test.Assert, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, a, b int64) innerProof {
	hash, err := poseidon.Hash([]*big.Int{big.NewInt(a), big.NewInt(b)})
	assert.NoError(err)

	full, err := frontend.NewWitness(&innerCircuitPlain{PublicInputHash: hash, A: a, B: b}, ecc.BN254.ScalarField())
	assert.NoError(err)
	proof, err := groth16.Prove(ccs, pk, full)
	assert.NoError(err)
	public, err := full.Public()
	assert.NoError(err)
	assert.NoError(groth16.Verify(proof, vk, public))

	return innerProof{witness: public, proof: proof, hash: hash}
}

// A mixed batch verifies each slot against its own key. It has a committed leg
// beside an uncommitted one, the P256-beside-eddsa case.
func TestAggregateVerifiesAMixedBatch(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	plainCcs, plainPk, plainVk := plainSystem(assert)
	batch := []innerProof{
		proveInner(assert, ccs, pk, vk, 3, 5),
		provePlain(assert, plainCcs, plainPk, plainVk, 7, 11),
	}

	mixed, err := NewCircuit(fixedKeys(assert, vk, plainVk))
	assert.NoError(err)
	assert.NoError(test.IsSolved(
		mixed,
		assignment(assert, batch, chain(assert, batch)),
		ecc.BN254.ScalarField(),
	))
}

// Slot order is part of the statement through the per-slot keys. Swapping two
// legs of different kinds recomputes a consistent chain, so only the fixed
// keys can reject the swap, and they must.
func TestAggregateRejectsMixedLegsInSwappedSlots(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	altCcs, altPk, altVk := altSystem(assert)
	swapped := []innerProof{
		proveAlt(assert, altCcs, altPk, altVk, 7, 11),
		proveInner(assert, ccs, pk, vk, 3, 5),
	}

	mixed, err := NewCircuit(fixedKeys(assert, vk, altVk))
	assert.NoError(err)
	assert.Error(test.IsSolved(
		mixed,
		assignment(assert, swapped, chain(assert, swapped)),
		ecc.BN254.ScalarField(),
	))
}

// The whole mixed pipeline runs real inner proofs of two kinds, outer setup,
// outer prove, and gnark's native verifier over the outer proof. The outer
// key must stay the one-commitment shape the shielded pool already parses,
// with the extra slot adding no second commitment.
func TestMixedAggregateOuterProofVerifiesNatively(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a multi-million constraint setup and prove")
	}
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	plainCcs, plainPk, plainVk := plainSystem(assert)
	batch := []innerProof{
		proveInner(assert, ccs, pk, vk, 3, 5),
		provePlain(assert, plainCcs, plainPk, plainVk, 7, 11),
	}

	mixed, err := NewCircuit(fixedKeys(assert, vk, plainVk))
	assert.NoError(err)
	outerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, mixed)
	assert.NoError(err)
	assert.Equal(1, len(outerCcs.GetCommitments().CommitmentIndexes()))

	outerPk, outerVk, err := groth16.Setup(outerCcs)
	assert.NoError(err)
	full, err := frontend.NewWitness(assignment(assert, batch, chain(assert, batch)), ecc.BN254.ScalarField())
	assert.NoError(err)
	proof, err := groth16.Prove(outerCcs, outerPk, full)
	assert.NoError(err)
	public, err := full.Public()
	assert.NoError(err)
	assert.NoError(groth16.Verify(proof, outerVk, public))
}

// Outer cost per batched proof depends on the inner circuit only through its
// public input count and its commitment count, not through its size. innerCircuit
// matches the P256 rail on both, so these counts carry over to the real
// circuits and set the proving key size and the proving time.
func TestAggregateConstraintCost(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles multi-million constraint circuits")
	}
	assert := test.NewAssert(t)
	ccs, _, vk := innerSystem(assert)

	// Pinned because setup memory and time scale with them.
	want := map[int]int{2: 2570169, 3: 3756865}

	previous := 0
	for _, n := range []int{2, 3} {
		outer, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, skeleton(assert, n, ccs, vk))
		assert.NoError(err)
		count := outer.GetNbConstraints()
		assert.Equal(want[n], count, "batch %d", n)
		if previous > 0 {
			t.Logf("batch %d: %d constraints, %d per added proof", n, count, count-previous)
		}
		previous = count
	}
}

func TestNewCircuitRejectsAnUnamortizedBatch(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, vk := innerSystem(assert)

	for _, n := range []int{0, 1} {
		vks := make([]groth16.VerifyingKey, n)
		for i := range vks {
			vks[i] = vk
		}
		_, err := NewCircuit(fixedKeys(assert, vks...))
		assert.Error(err, "batch size %d", n)
	}
}
