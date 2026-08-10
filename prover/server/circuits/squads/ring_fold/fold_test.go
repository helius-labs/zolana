package squads_ring_fold

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

// legCircuit stands in for the ring circuit. It exposes the same single public
// input, HashChain over the transfer-shape preimage, plus a commitment over
// private wires. The commitment is what the real circuit gets from its emulated
// P-256 arithmetic, and it is what makes a folded proof exercise the native
// hash-to-field path. Standing in keeps the test off an emulated-curve circuit.
type legCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	Preimage [TransferPreimageLen]frontend.Variable
}

func (c *legCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, c.Preimage[:]))
	commitment, err := api.(frontend.Committer).Commit(c.Preimage[0])
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)
	return nil
}

// leg is one proved ring spend and the preimage it committed to.
type leg struct {
	preimage []*big.Int
	witness  witness.Witness
	proof    groth16.Proof
}

func innerSystem(assert *test.Assert) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &legCircuit{})
	assert.NoError(err)
	assert.Equal(1, len(ccs.GetCommitments().CommitmentIndexes()))
	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)
	return ccs, pk, vk
}

func chain(assert *test.Assert, values []*big.Int) *big.Int {
	acc := values[0]
	for _, v := range values[1:] {
		next, err := poseidon.Hash([]*big.Int{acc, v})
		assert.NoError(err)
		acc = next
	}
	return acc
}

func proveLeg(
	assert *test.Assert,
	ccs constraint.ConstraintSystem,
	pk groth16.ProvingKey,
	vk groth16.VerifyingKey,
	preimage []*big.Int,
) leg {
	assert.Equal(TransferPreimageLen, len(preimage))
	public := chain(assert, preimage)

	assignment := &legCircuit{PublicInputHash: public}
	for i, value := range preimage {
		assignment.Preimage[i] = value
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	proof, err := groth16.Prove(ccs, pk, full)
	assert.NoError(err)
	pub, err := full.Public()
	assert.NoError(err)
	assert.NoError(groth16.Verify(proof, vk, pub))

	return leg{preimage: preimage, witness: pub, proof: proof}
}

// spend builds one leg preimage from the shared sender and recipient identities
// around the leg's own transaction fields, with no proposal.
func spend(tag int64) []*big.Int {
	preimage := make([]*big.Int, TransferPreimageLen)
	preimage[PrivateTxHashIndex] = big.NewInt(tag)
	preimage[PublicAmountIndex] = big.NewInt(0)
	preimage[SenderAccountIndex] = big.NewInt(7000)
	preimage[SenderCiphertextIndex] = big.NewInt(tag + 1)
	preimage[TxViewingPkLoIndex] = big.NewInt(tag + 2)
	preimage[TxViewingPkHiIndex] = big.NewInt(tag + 3)
	preimage[RecipientAccountIndex] = big.NewInt(8000)
	preimage[RecipientCiphertextIndex] = big.NewInt(tag + 4)
	preimage[TransferProposalIndex] = big.NewInt(0)
	return preimage
}

func skeleton(assert *test.Assert, legs int, ccs constraint.ConstraintSystem, vk groth16.VerifyingKey) *Circuit {
	fixed, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
	assert.NoError(err)
	c, err := NewCircuit(legs, TransferOutputs, fixed, ccs)
	assert.NoError(err)
	return c
}

// assignment fills a fold. foldHash is passed separately so a test can claim a
// run the legs do not prove.
func assignment(assert *test.Assert, legs []leg, foldHash *big.Int) *Circuit {
	c := &Circuit{
		FoldInputHash: foldHash,
		Proofs:        make([]InnerProof, len(legs)),
		Witnesses:     make([]InnerWitness, len(legs)),
		Preimages:     make([][]frontend.Variable, len(legs)),
		NumOutputs:    TransferOutputs,
	}
	for i, l := range legs {
		p, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](l.proof)
		assert.NoError(err)
		w, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](l.witness)
		assert.NoError(err)
		c.Proofs[i], c.Witnesses[i] = p, w
		c.Preimages[i] = make([]frontend.Variable, TransferPreimageLen)
		for j, value := range l.preimage {
			c.Preimages[i][j] = value
		}
	}
	return c
}

// foldHash is the shared sender and recipient once, then each leg's own fields
// in leg order.
func foldHash(assert *test.Assert, legs []leg) *big.Int {
	elements := []*big.Int{
		legs[0].preimage[SenderAccountIndex],
		legs[0].preimage[RecipientAccountIndex],
	}
	for _, l := range legs {
		elements = append(elements,
			l.preimage[PrivateTxHashIndex],
			l.preimage[PublicAmountIndex],
			l.preimage[SenderCiphertextIndex],
			l.preimage[TxViewingPkLoIndex],
			l.preimage[TxViewingPkHiIndex],
			l.preimage[RecipientCiphertextIndex],
		)
	}
	return chain(assert, elements)
}

// agreeing is a run of spends of one account to one recipient.
func agreeing(assert *test.Assert, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) []leg {
	return []leg{
		proveLeg(assert, ccs, pk, vk, spend(100)),
		proveLeg(assert, ccs, pk, vk, spend(200)),
	}
}

func TestFoldVerifiesAgreeingLegs(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	legs := agreeing(assert, ccs, pk, vk)

	assert.NoError(test.IsSolved(
		skeleton(assert, len(legs), ccs, vk),
		assignment(assert, legs, foldHash(assert, legs)),
		ecc.BN254.ScalarField(),
	))
}

// rejects proves one guard is load bearing. The second leg is changed at
// position, and the fold must not solve even though the claimed run still
// chains leg 0's identities.
func rejects(t *testing.T, position int, value int64) {
	t.Helper()
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)

	second := spend(200)
	second[position] = big.NewInt(value)
	legs := []leg{
		proveLeg(assert, ccs, pk, vk, spend(100)),
		proveLeg(assert, ccs, pk, vk, second),
	}

	assert.Error(test.IsSolved(
		skeleton(assert, len(legs), ccs, vk),
		assignment(assert, legs, foldHash(assert, legs)),
		ecc.BN254.ScalarField(),
	))
}

// The sender identity is what the program checks against the on-chain viewing
// key account, and it checks it once. A leg spending another account would
// settle UTXOs the program never authorized.
func TestFoldRejectsADisagreeingSender(t *testing.T) {
	rejects(t, SenderAccountIndex, 7001)
}

// The recipient identity is read from leg 0 too, so a leg paying elsewhere
// would divert its output while the program still sees the checked recipient.
func TestFoldRejectsADisagreeingRecipient(t *testing.T) {
	rejects(t, RecipientAccountIndex, 8001)
}

// A proposal commits to one operation. Folding legs under it would settle the
// committed amount once per leg.
func TestFoldRejectsALegCarryingAProposal(t *testing.T) {
	rejects(t, TransferProposalIndex, 1234)
}

// The first leg is guarded too, so a proposal cannot enter through it.
func TestFoldRejectsAProposalOnTheFirstLeg(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)

	first := spend(100)
	first[TransferProposalIndex] = big.NewInt(1234)
	legs := []leg{
		proveLeg(assert, ccs, pk, vk, first),
		proveLeg(assert, ccs, pk, vk, spend(200)),
	}

	assert.Error(test.IsSolved(
		skeleton(assert, len(legs), ccs, vk),
		assignment(assert, legs, foldHash(assert, legs)),
		ecc.BN254.ScalarField(),
	))
}

// The preimage is bound to the proof, so a leg cannot restate its spend.
// Without the binding every equality above would be vacuous.
func TestFoldRejectsAPreimageTheProofDidNotCommitTo(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	legs := agreeing(assert, ccs, pk, vk)

	tampered := assignment(assert, legs, foldHash(assert, legs))
	tampered.Preimages[1][PrivateTxHashIndex] = big.NewInt(999)

	assert.Error(test.IsSolved(
		skeleton(assert, len(legs), ccs, vk),
		tampered,
		ecc.BN254.ScalarField(),
	))
}

// The run is the statement the program settles. It is a left fold, so leg order
// is part of it.
func TestFoldRejectsReorderedLegs(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	legs := agreeing(assert, ccs, pk, vk)
	reordered := []leg{legs[1], legs[0]}

	assert.Error(test.IsSolved(
		skeleton(assert, len(legs), ccs, vk),
		assignment(assert, reordered, foldHash(assert, legs)),
		ecc.BN254.ScalarField(),
	))
}

func TestFoldRejectsAWrongFoldHash(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	legs := agreeing(assert, ccs, pk, vk)

	assert.Error(test.IsSolved(
		skeleton(assert, len(legs), ccs, vk),
		assignment(assert, legs, new(big.Int).Add(foldHash(assert, legs), big.NewInt(1))),
		ecc.BN254.ScalarField(),
	))
}

// A proof from another proving key must not pass under the fixed key.
func TestFoldRejectsAProofForAnotherKey(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	_, otherPk, otherVk := innerSystem(assert)

	legs := []leg{
		proveLeg(assert, ccs, pk, vk, spend(100)),
		proveLeg(assert, ccs, otherPk, otherVk, spend(200)),
	}

	assert.Error(test.IsSolved(
		skeleton(assert, len(legs), ccs, vk),
		assignment(assert, legs, foldHash(assert, legs)),
		ecc.BN254.ScalarField(),
	))
}

func TestNewCircuitRejectsAnUnsupportedShape(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, _, vk := innerSystem(assert)
	fixed, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
	assert.NoError(err)

	for _, legs := range []int{0, 1} {
		_, err := NewCircuit(legs, TransferOutputs, fixed, ccs)
		assert.Error(err, "%d legs", legs)
	}
	for _, outputs := range []int{0, 3} {
		_, err := NewCircuit(2, outputs, fixed, ccs)
		assert.Error(err, "%d outputs", outputs)
	}
}
