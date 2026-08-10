package squads_key_encryption_fold

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

// Recipients per leg the tests compile against.
const testKeysPerLeg = 2

// The array bound of the stand-in circuit needs a constant, so this restates
// PreimageLen(testKeysPerLeg).
const preimageLen = PrefixLen + KeyFields*testKeysPerLeg + SuffixLen

// legCircuit stands in for the key-encryption circuit. It exposes the same
// single public input, HashChain over the shared prefix, the recipient triples,
// and the shared suffix, plus a commitment over private wires. The commitment
// is what the real circuit gets from its emulated P-256 arithmetic, and it is
// what makes a folded proof exercise the native hash-to-field path. Standing in
// keeps the test off an emulated-curve circuit.
type legCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	Preimage [preimageLen]frontend.Variable
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

// leg is one proved key-encryption statement and the preimage it committed to.
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
	assert.Equal(preimageLen, len(preimage))
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

// account is the shared half of a leg preimage. That half is prior state,
// shared viewing key and its commitment, shared ephemeral key, then the
// nullifier pair.
type account struct {
	prefix [PrefixLen]int64
	suffix [SuffixLen]int64
}

func defaultAccount() account {
	return account{
		prefix: [PrefixLen]int64{10, 11, 12, 13, 14, 15},
		suffix: [SuffixLen]int64{90, 91},
	}
}

// preimage builds one leg's public-input preimage from the account's shared
// fields around keysPerLeg recipient triples starting at firstKey.
func (a account) preimage(firstKey int64) []*big.Int {
	out := make([]*big.Int, 0, preimageLen)
	for _, v := range a.prefix {
		out = append(out, big.NewInt(v))
	}
	for i := 0; i < testKeysPerLeg*KeyFields; i++ {
		out = append(out, big.NewInt(firstKey+int64(i)))
	}
	for _, v := range a.suffix {
		out = append(out, big.NewInt(v))
	}
	return out
}

func skeleton(assert *test.Assert, legs int, ccs constraint.ConstraintSystem, vk groth16.VerifyingKey) *Circuit {
	fixed, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
	assert.NoError(err)
	c, err := NewCircuit(legs, testKeysPerLeg, fixed, ccs)
	assert.NoError(err)
	return c
}

// assignment fills a fold. foldHash is passed separately so a test can claim a
// union the legs do not prove.
func assignment(assert *test.Assert, legs []leg, foldHash *big.Int) *Circuit {
	c := &Circuit{
		FoldInputHash: foldHash,
		Proofs:        make([]InnerProof, len(legs)),
		Witnesses:     make([]InnerWitness, len(legs)),
		Preimages:     make([][]frontend.Variable, len(legs)),
		KeysPerLeg:    testKeysPerLeg,
	}
	for i, l := range legs {
		p, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](l.proof)
		assert.NoError(err)
		w, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](l.witness)
		assert.NoError(err)
		c.Proofs[i], c.Witnesses[i] = p, w
		c.Preimages[i] = make([]frontend.Variable, preimageLen)
		for j, value := range l.preimage {
			c.Preimages[i][j] = value
		}
	}
	return c
}

// foldHash is the chain a single circuit over every leg's recipients would
// expose. The shared fields come once, then the triples in leg order.
func foldHash(assert *test.Assert, legs []leg) *big.Int {
	keyEnd := PrefixLen + KeyFields*testKeysPerLeg
	elements := make([]*big.Int, 0)
	elements = append(elements, legs[0].preimage[:PrefixLen]...)
	for _, l := range legs {
		elements = append(elements, l.preimage[PrefixLen:keyEnd]...)
	}
	elements = append(elements, legs[0].preimage[keyEnd:]...)
	return chain(assert, elements)
}

// agreeing is a fold of legs that describe one account and differ only in their
// recipient triples.
func agreeing(assert *test.Assert, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) []leg {
	a := defaultAccount()
	return []leg{
		proveLeg(assert, ccs, pk, vk, a.preimage(100)),
		proveLeg(assert, ccs, pk, vk, a.preimage(200)),
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

// rejectsDisagreementAt proves the guard on one shared position is load
// bearing. A leg that changes it must not fold, even though the claimed union
// still chains leg 0's shared fields.
func rejectsDisagreementAt(t *testing.T, position int) {
	t.Helper()
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)

	a := defaultAccount()
	first := a.preimage(100)
	second := a.preimage(200)
	second[position] = new(big.Int).Add(second[position], big.NewInt(1))

	legs := []leg{
		proveLeg(assert, ccs, pk, vk, first),
		proveLeg(assert, ccs, pk, vk, second),
	}

	assert.Error(test.IsSolved(
		skeleton(assert, len(legs), ccs, vk),
		assignment(assert, legs, foldHash(assert, legs)),
		ecc.BN254.ScalarField(),
	))
}

// The prior state is what a rotation binds against. Legs that bind different
// states describe two rotations, and settling them as one would apply an update
// the account never held.
func TestFoldRejectsADisagreeingOldStateHash(t *testing.T) {
	rejectsDisagreementAt(t, oldStateHashIndex)
}

// The shared viewing key is the secret every recipient is meant to receive. A
// leg encrypting a different one hands part of the recipient set a key that
// opens nothing.
func TestFoldRejectsADisagreeingSharedViewingKey(t *testing.T) {
	rejectsDisagreementAt(t, sharedPkLoIndex)
	rejectsDisagreementAt(t, sharedPkHiIndex)
}

// The commitment is what the account publishes for the viewing secret. A leg
// committing to another secret breaks the binding the ring proof relies on.
func TestFoldRejectsADisagreeingCommitment(t *testing.T) {
	rejectsDisagreementAt(t, commitmentIndex)
}

// One ephemeral key covers every ciphertext, and the account stores exactly
// one. A leg under another ephemeral produces ciphertexts no holder can open
// from the stored key.
func TestFoldRejectsADisagreeingEphemeralKey(t *testing.T) {
	rejectsDisagreementAt(t, ephPkLoIndex)
	rejectsDisagreementAt(t, ephPkHiIndex)
}

// The account holds one nullifier pubkey and one encrypted nullifier secret.
// Legs that disagree describe two accounts.
func TestFoldRejectsADisagreeingNullifierPair(t *testing.T) {
	keyEnd := PrefixLen + KeyFields*testKeysPerLeg
	rejectsDisagreementAt(t, keyEnd)
	rejectsDisagreementAt(t, keyEnd+1)
}

// The preimage is bound to the proof, so a leg cannot restate its recipients.
// Without the binding every equality above would be vacuous.
func TestFoldRejectsAPreimageTheProofDidNotCommitTo(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, pk, vk := innerSystem(assert)
	legs := agreeing(assert, ccs, pk, vk)

	tampered := assignment(assert, legs, foldHash(assert, legs))
	tampered.Preimages[1][PrefixLen] = big.NewInt(999)

	assert.Error(test.IsSolved(
		skeleton(assert, len(legs), ccs, vk),
		tampered,
		ecc.BN254.ScalarField(),
	))
}

// The union is the statement the program acts on. It is a left fold, so leg
// order is part of it.
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

	a := defaultAccount()
	legs := []leg{
		proveLeg(assert, ccs, pk, vk, a.preimage(100)),
		proveLeg(assert, ccs, otherPk, otherVk, a.preimage(200)),
	}

	assert.Error(test.IsSolved(
		skeleton(assert, len(legs), ccs, vk),
		assignment(assert, legs, foldHash(assert, legs)),
		ecc.BN254.ScalarField(),
	))
}

func TestNewCircuitRejectsAnUnamortizedFold(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, _, vk := innerSystem(assert)
	fixed, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
	assert.NoError(err)

	for _, legs := range []int{0, 1} {
		_, err := NewCircuit(legs, testKeysPerLeg, fixed, ccs)
		assert.Error(err, "%d legs", legs)
	}
	_, err = NewCircuit(2, 0, fixed, ccs)
	assert.Error(err, "0 keys per leg")
}
