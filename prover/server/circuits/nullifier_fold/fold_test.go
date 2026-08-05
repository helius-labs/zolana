package nullifier_fold

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

// The batch size the fold's StartIndex step is compiled against.
const testBatchSize = 4

// appendCircuit stands in for BatchAddressTreeAppendCircuit. It exposes the
// same single public input, HashChain over the four span fields, which is all
// the fold reads. Standing in keeps the test off a 40-deep Merkle circuit.
type appendCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	OldRoot       frontend.Variable
	NewRoot       frontend.Variable
	HashchainHash frontend.Variable
	StartIndex    frontend.Variable
}

func (c *appendCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, []frontend.Variable{
		c.OldRoot, c.NewRoot, c.HashchainHash, c.StartIndex,
	}))
	return nil
}

type span struct {
	oldRoot, newRoot, hashchain, startIndex *big.Int
	witness                                 witness.Witness
	proof                                   groth16.Proof
}

func innerSystem(assert *test.Assert) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &appendCircuit{})
	assert.NoError(err)
	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)
	return ccs, pk, vk
}

func chain(assert *test.Assert, values ...*big.Int) *big.Int {
	acc := values[0]
	for _, v := range values[1:] {
		next, err := poseidon.Hash([]*big.Int{acc, v})
		assert.NoError(err)
		acc = next
	}
	return acc
}

func proveAppend(
	assert *test.Assert,
	ccs constraint.ConstraintSystem,
	pk groth16.ProvingKey,
	vk groth16.VerifyingKey,
	oldRoot, newRoot, hashchainHash, startIndex int64,
) span {
	o, n := big.NewInt(oldRoot), big.NewInt(newRoot)
	h, s := big.NewInt(hashchainHash), big.NewInt(startIndex)
	public := chain(assert, o, n, h, s)

	full, err := frontend.NewWitness(&appendCircuit{
		PublicInputHash: public, OldRoot: o, NewRoot: n, HashchainHash: h, StartIndex: s,
	}, ecc.BN254.ScalarField())
	assert.NoError(err)
	proof, err := groth16.Prove(ccs, pk, full)
	assert.NoError(err)
	pub, err := full.Public()
	assert.NoError(err)
	assert.NoError(groth16.Verify(proof, vk, pub))

	return span{oldRoot: o, newRoot: n, hashchain: h, startIndex: s, witness: pub, proof: proof}
}

func skeleton(assert *test.Assert, n int, ccs constraint.ConstraintSystem, vk groth16.VerifyingKey) *Circuit {
	fixed, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
	assert.NoError(err)
	c, err := NewCircuit(n, testBatchSize, fixed, ccs)
	assert.NoError(err)
	return c
}

// assignment fills a run. foldHash is passed separately so a test can claim a
// span the run does not prove.
func assignment(assert *test.Assert, run []span, foldHash *big.Int) *Circuit {
	c := &Circuit{
		FoldInputHash: foldHash,
		Proofs:        make([]InnerProof, len(run)),
		Witnesses:     make([]InnerWitness, len(run)),
		Preimages:     make([][PreimageLen]frontend.Variable, len(run)),
		BatchSize:     testBatchSize,
	}
	for i, leg := range run {
		p, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](leg.proof)
		assert.NoError(err)
		w, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](leg.witness)
		assert.NoError(err)
		c.Proofs[i], c.Witnesses[i] = p, w
		c.Preimages[i] = [PreimageLen]frontend.Variable{
			leg.oldRoot, leg.newRoot, leg.hashchain, leg.startIndex,
		}
	}
	return c
}

func foldHash(assert *test.Assert, run []span) *big.Int {
	elements := make([]*big.Int, len(run))
	for i, leg := range run {
		elements[i] = leg.hashchain
	}
	return chain(assert,
		run[0].oldRoot,
		run[len(run)-1].newRoot,
		chain(assert, elements...),
		run[0].startIndex,
	)
}

// A consecutive run. Each leg starts where the previous ended, in both the root
// and the index.
func consecutive(assert *test.Assert, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) []span {
	return []span{
		proveAppend(assert, ccs, pk, vk, 100, 200, 11, 0),
		proveAppend(assert, ccs, pk, vk, 200, 300, 22, testBatchSize),
		proveAppend(assert, ccs, pk, vk, 300, 400, 33, 2*testBatchSize),
	}
}

func TestFoldVerifiesAConsecutiveRun(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	run := consecutive(assert, ccs, pk, vk)

	assert.NoError(test.IsSolved(
		skeleton(assert, len(run), ccs, vk),
		assignment(assert, run, foldHash(assert, run)),
		ecc.BN254.ScalarField(),
	))
}

// Root continuity makes the span meaningful. A gap would let a fold
// expose endpoints the tree never travelled between.
func TestFoldRejectsARootGap(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	run := []span{
		proveAppend(assert, ccs, pk, vk, 100, 200, 11, 0),
		proveAppend(assert, ccs, pk, vk, 999, 300, 22, testBatchSize),
	}

	assert.Error(test.IsSolved(
		skeleton(assert, len(run), ccs, vk),
		assignment(assert, run, foldHash(assert, run)),
		ecc.BN254.ScalarField(),
	))
}

// Index continuity stops a leg replaying another leg's elements at the wrong
// offset while the roots still line up.
func TestFoldRejectsAnIndexGap(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	run := []span{
		proveAppend(assert, ccs, pk, vk, 100, 200, 11, 0),
		proveAppend(assert, ccs, pk, vk, 200, 300, 22, testBatchSize+1),
	}

	assert.Error(test.IsSolved(
		skeleton(assert, len(run), ccs, vk),
		assignment(assert, run, foldHash(assert, run)),
		ecc.BN254.ScalarField(),
	))
}

// The preimage is bound to the proof, so a leg cannot restate its span.
func TestFoldRejectsAPreimageTheProofDidNotCommitTo(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	run := consecutive(assert, ccs, pk, vk)

	tampered := assignment(assert, run, foldHash(assert, run))
	tampered.Preimages[1][hashchainIndex] = big.NewInt(999)

	assert.Error(test.IsSolved(
		skeleton(assert, len(run), ccs, vk),
		tampered,
		ecc.BN254.ScalarField(),
	))
}

// The claimed span is the whole statement the program acts on.
func TestFoldRejectsAWrongFoldHash(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	run := consecutive(assert, ccs, pk, vk)

	assert.Error(test.IsSolved(
		skeleton(assert, len(run), ccs, vk),
		assignment(assert, run, new(big.Int).Add(foldHash(assert, run), big.NewInt(1))),
		ecc.BN254.ScalarField(),
	))
}

func TestFoldRejectsAProofForAnotherKey(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	_, otherPk, otherVk := innerSystem(assert)

	run := []span{
		proveAppend(assert, ccs, pk, vk, 100, 200, 11, 0),
		proveAppend(assert, ccs, otherPk, otherVk, 200, 300, 22, testBatchSize),
	}

	assert.Error(test.IsSolved(
		skeleton(assert, len(run), ccs, vk),
		assignment(assert, run, foldHash(assert, run)),
		ecc.BN254.ScalarField(),
	))
}

func TestNewCircuitRejectsAnUnamortizedRun(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, _, vk := innerSystem(assert)
	fixed, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
	assert.NoError(err)

	for _, n := range []int{0, 1} {
		_, err := NewCircuit(n, testBatchSize, fixed, ccs)
		assert.Error(err, "run of %d", n)
	}
}
