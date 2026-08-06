package merge_chain

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

// mergeCircuit stands in for the default merge circuit. It exposes the same
// single public input, HashChain over the eight preimage fields, which is all
// the chain reads. Standing in keeps every guard below independent, so a test
// that breaks one predicate cannot fail on a predicate the real merge would
// have enforced anyway.
type mergeCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	Fields [PreimageLen]frontend.Variable
}

func (c *mergeCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, c.Fields[:]))
	return nil
}

// leg is one proved merge together with the per-slot values its preimage folds.
type leg struct {
	nullifiers     [Slots]*big.Int
	utxoRoots      [Slots]*big.Int
	nullifierRoots [Slots]*big.Int
	inputHashes    [Slots]*big.Int
	fields         [PreimageLen]*big.Int

	witness witness.Witness
	proof   groth16.Proof
}

type innerSystem struct {
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
}

func newInnerSystem(assert *test.Assert) innerSystem {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &mergeCircuit{})
	assert.NoError(err)
	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)
	return innerSystem{ccs: ccs, pk: pk, vk: vk}
}

// shared is the per-proof identity every leg of a chain must agree on.
type shared struct {
	externalDataHash *big.Int
	allowDummyInputs *big.Int
	signingPkHash    *big.Int
}

func defaultShared() shared {
	return shared{
		externalDataHash: big.NewInt(7001),
		allowDummyInputs: big.NewInt(1),
		signingPkHash:    big.NewInt(7002),
	}
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

func chainOf(assert *test.Assert, values [Slots]*big.Int) *big.Int {
	return chain(assert, values[:]...)
}

// privateTxHash mirrors the merge's fold. The address side is eight empty
// slots, because a merge spends no addresses.
func privateTxHash(assert *test.Assert, inputs [Slots]*big.Int, output, externalDataHash *big.Int) *big.Int {
	var addresses [Slots]*big.Int
	for i := range addresses {
		addresses[i] = big.NewInt(0)
	}
	h, err := poseidon.Hash([]*big.Int{
		chainOf(assert, inputs), output, chainOf(assert, addresses), externalDataHash,
	})
	assert.NoError(err)
	return h
}

// proveLeg builds one merge over per-slot values seeded by tag, lets adjust
// edit them, then folds and proves what adjust left behind. Every value is
// arbitrary. The stand-in merge constrains none of them, and the chain
// constrains only their folds.
func proveLeg(assert *test.Assert, inner innerSystem, s shared, tag int64, adjust func(*leg)) leg {
	var l leg
	for i := 0; i < Slots; i++ {
		l.nullifiers[i] = big.NewInt(tag*1000 + int64(i))
		l.utxoRoots[i] = big.NewInt(tag*1000 + 100 + int64(i))
		l.nullifierRoots[i] = big.NewInt(tag*1000 + 200 + int64(i))
		l.inputHashes[i] = big.NewInt(tag*1000 + 300 + int64(i))
	}
	l.fields[OutputHashIndex] = big.NewInt(tag*1000 + 400)
	if adjust != nil {
		adjust(&l)
	}

	output := l.fields[OutputHashIndex]
	l.fields = [PreimageLen]*big.Int{
		NullifierChainIndex:     chainOf(assert, l.nullifiers),
		OutputHashIndex:         output,
		UtxoRootChainIndex:      chainOf(assert, l.utxoRoots),
		NullifierRootChainIndex: chainOf(assert, l.nullifierRoots),
		PrivateTxHashIndex:      privateTxHash(assert, l.inputHashes, output, s.externalDataHash),
		ExternalDataHashIndex:   s.externalDataHash,
		AllowDummyInputsIndex:   s.allowDummyInputs,
		SigningPkHashIndex:      s.signingPkHash,
	}

	assignment := &mergeCircuit{PublicInputHash: chain(assert, l.fields[:]...)}
	for i, f := range l.fields {
		assignment.Fields[i] = f
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	l.proof, err = groth16.Prove(inner.ccs, inner.pk, full)
	assert.NoError(err)
	l.witness, err = full.Public()
	assert.NoError(err)
	assert.NoError(groth16.Verify(l.proof, inner.vk, l.witness))
	return l
}

func feed(shape Shape, legs []leg, i int) func(*leg) {
	return func(l *leg) {
		for slot := 0; slot < Slots; slot++ {
			if source, chained := shape.Source(i, slot); chained {
				l.inputHashes[slot] = legs[source].fields[OutputHashIndex]
			}
		}
	}
}

// proveChain fills shape bottom up, which is the order the chained slots need.
func proveChain(assert *test.Assert, inner innerSystem, s shared, shape Shape) []leg {
	legs := make([]leg, shape.Legs())
	for i := range legs {
		legs[i] = proveLeg(assert, inner, s, int64(i+1), feed(shape, legs, i))
	}
	return legs
}

func skeleton(assert *test.Assert, inner innerSystem, shape Shape) *Circuit {
	fixed, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](inner.vk)
	assert.NoError(err)
	c, err := NewCircuit(shape, fixed, inner.ccs)
	assert.NoError(err)
	return c
}

// assignment fills a chain. chainHash is passed separately so a test can claim
// a statement the chain does not prove.
func assignment(assert *test.Assert, shape Shape, legs []leg, chainHash *big.Int) *Circuit {
	c := &Circuit{
		MergeChainInputHash: chainHash,
		Proofs:              make([]InnerProof, len(legs)),
		Witnesses:           make([]InnerWitness, len(legs)),
		Preimages:           make([][PreimageLen]frontend.Variable, len(legs)),
		Nullifiers:          make([][Slots]frontend.Variable, len(legs)),
		UtxoRoots:           make([][Slots]frontend.Variable, len(legs)),
		NullifierRoots:      make([][Slots]frontend.Variable, len(legs)),
		InputHashes:         make([][Slots]frontend.Variable, len(legs)),
		Shape:               shape,
	}
	for i, l := range legs {
		p, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](l.proof)
		assert.NoError(err)
		w, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](l.witness)
		assert.NoError(err)
		c.Proofs[i], c.Witnesses[i] = p, w
		for j, f := range l.fields {
			c.Preimages[i][j] = f
		}
		for s := 0; s < Slots; s++ {
			c.Nullifiers[i][s] = l.nullifiers[s]
			c.UtxoRoots[i][s] = l.utxoRoots[s]
			c.NullifierRoots[i][s] = l.nullifierRoots[s]
			c.InputHashes[i][s] = l.inputHashes[s]
		}
	}
	return c
}

// chainHash folds the statement the shielded pool recomputes. The statement is
// the tree-backed slots in leg then slot order, the top output, and the shared
// identity.
func chainHash(assert *test.Assert, shape Shape, legs []leg) *big.Int {
	var nullifiers, utxoRoots, nullifierRoots, privateTxHashes []*big.Int
	for i, l := range legs {
		privateTxHashes = append(privateTxHashes, l.fields[PrivateTxHashIndex])
		for s := 0; s < Slots; s++ {
			if _, chained := shape.Source(i, s); chained {
				continue
			}
			nullifiers = append(nullifiers, l.nullifiers[s])
			utxoRoots = append(utxoRoots, l.utxoRoots[s])
			nullifierRoots = append(nullifierRoots, l.nullifierRoots[s])
		}
	}
	return chain(assert,
		chain(assert, nullifiers...),
		legs[len(legs)-1].fields[OutputHashIndex],
		chain(assert, utxoRoots...),
		chain(assert, nullifierRoots...),
		chain(assert, privateTxHashes...),
		legs[0].fields[ExternalDataHashIndex],
		legs[0].fields[AllowDummyInputsIndex],
		legs[0].fields[SigningPkHashIndex],
	)
}

func mustShape(assert *test.Assert, levels ...int) Shape {
	shape, err := NewShape(levels)
	assert.NoError(err)
	return shape
}

// solve runs an honest chain through the circuit, with mutate applied to the
// assignment first so a test can name exactly one departure.
func solve(assert *test.Assert, inner innerSystem, shape Shape, legs []leg, mutate func(*Circuit)) error {
	c := assignment(assert, shape, legs, chainHash(assert, shape, legs))
	if mutate != nil {
		mutate(c)
	}
	return test.IsSolved(skeleton(assert, inner, shape), c, ecc.BN254.ScalarField())
}

func TestChainVerifiesALinearChain(t *testing.T) {
	assert := test.NewAssert(t)
	inner := newInnerSystem(assert)
	shape := mustShape(assert, 1, 1)
	legs := proveChain(assert, inner, defaultShared(), shape)

	assert.Equal(2, shape.Legs())
	assert.Equal(15, shape.TreeInputs())
	assert.NoError(solve(assert, inner, shape, legs, nil))
}

func TestChainVerifiesABranchingTree(t *testing.T) {
	assert := test.NewAssert(t)
	inner := newInnerSystem(assert)
	shape := mustShape(assert, 2, 1)
	legs := proveChain(assert, inner, defaultShared(), shape)

	assert.Equal(3, shape.Legs())
	assert.Equal(22, shape.TreeInputs())
	assert.NoError(solve(assert, inner, shape, legs, nil))
}

// The chained slot spends a UTXO no tree holds, so this equality is the only
// thing that says the UTXO ever existed.
func TestChainRejectsASlotTheLevelBelowDidNotProduce(t *testing.T) {
	assert := test.NewAssert(t)
	inner := newInnerSystem(assert)
	shape := mustShape(assert, 1, 1)
	s := defaultShared()

	bottom := proveLeg(assert, inner, s, 1, nil)
	top := proveLeg(assert, inner, s, 2, func(l *leg) {
		l.inputHashes[Slots-1] = big.NewInt(999)
	})

	assert.Error(solve(assert, inner, shape, []leg{bottom, top}, nil))
}

// The preimage is bound to the proof, so a leg cannot restate its statement.
// The restatement here is internally consistent, folds and outer hash included,
// so only that binding stands against it.
func TestChainRejectsAPreimageTheProofDidNotCommitTo(t *testing.T) {
	assert := test.NewAssert(t)
	inner := newInnerSystem(assert)
	shape := mustShape(assert, 1, 1)
	legs := proveChain(assert, inner, defaultShared(), shape)

	legs[0].nullifiers[0] = big.NewInt(999)
	legs[0].fields[NullifierChainIndex] = chainOf(assert, legs[0].nullifiers)

	assert.Error(solve(assert, inner, shape, legs, nil))
}

// Each per-slot vector is opened against the fold the proof committed to.
// Without the opening a leg could drop a nullifier from the transaction, claim
// a root the pool never resolved, or rename the UTXO a chained slot spends. The
// outer hash is recomputed over the tampered vector, so only the opening
// separates them.
func TestChainRejectsATamperedSlotVector(t *testing.T) {
	assert := test.NewAssert(t)
	inner := newInnerSystem(assert)
	shape := mustShape(assert, 1, 1)
	legs := proveChain(assert, inner, defaultShared(), shape)

	vectors := map[string]func(*leg){
		"nullifiers":     func(l *leg) { l.nullifiers[0] = big.NewInt(999) },
		"utxoRoots":      func(l *leg) { l.utxoRoots[0] = big.NewInt(999) },
		"nullifierRoots": func(l *leg) { l.nullifierRoots[0] = big.NewInt(999) },
		"inputHashes":    func(l *leg) { l.inputHashes[0] = big.NewInt(999) },
	}
	for name, mutate := range vectors {
		tampered := append([]leg(nil), legs...)
		mutate(&tampered[0])
		assert.Error(solve(assert, inner, shape, tampered, nil), name)
	}
}

// The pool resolves one external data hash, one dummy policy, and one signing
// key for the whole transaction, so a leg that named another would settle
// against a value nothing checked.
func TestChainRejectsALegThatDisagreesOnTheSharedIdentity(t *testing.T) {
	assert := test.NewAssert(t)
	inner := newInnerSystem(assert)
	shape := mustShape(assert, 1, 1)
	base := defaultShared()

	divergent := map[string]shared{
		"externalDataHash": {big.NewInt(8001), base.allowDummyInputs, base.signingPkHash},
		"allowDummyInputs": {base.externalDataHash, big.NewInt(0), base.signingPkHash},
		"signingPkHash":    {base.externalDataHash, base.allowDummyInputs, big.NewInt(8002)},
	}
	for name, other := range divergent {
		bottom := proveLeg(assert, inner, base, 1, nil)
		legs := []leg{bottom, {}}
		legs[1] = proveLeg(assert, inner, other, 2, feed(shape, legs, 1))
		assert.Error(solve(assert, inner, shape, legs, nil), name)
	}
}

// A repeat across legs would sum one UTXO twice into the top output. A single
// merge rejects a repeat within its own eight, and nothing else would.
func TestChainRejectsANullifierSpentTwice(t *testing.T) {
	assert := test.NewAssert(t)
	inner := newInnerSystem(assert)
	shape := mustShape(assert, 1, 1)
	s := defaultShared()

	bottom := proveLeg(assert, inner, s, 1, nil)
	legs := []leg{bottom, {}}
	legs[1] = proveLeg(assert, inner, s, 2, func(l *leg) {
		feed(shape, legs, 1)(l)
		l.nullifiers[0] = bottom.nullifiers[0]
	})

	assert.Error(solve(assert, inner, shape, legs, nil))
}

// The claimed statement is what the program acts on.
func TestChainRejectsAWrongChainHash(t *testing.T) {
	assert := test.NewAssert(t)
	inner := newInnerSystem(assert)
	shape := mustShape(assert, 1, 1)
	legs := proveChain(assert, inner, defaultShared(), shape)

	assert.Error(test.IsSolved(
		skeleton(assert, inner, shape),
		assignment(assert, shape, legs, new(big.Int).Add(chainHash(assert, shape, legs), big.NewInt(1))),
		ecc.BN254.ScalarField(),
	))
}

// A proof from another proving key must not pass under the fixed key.
func TestChainRejectsAProofForAnotherKey(t *testing.T) {
	assert := test.NewAssert(t)
	inner := newInnerSystem(assert)
	other := newInnerSystem(assert)
	shape := mustShape(assert, 1, 1)
	s := defaultShared()

	bottom := proveLeg(assert, inner, s, 1, nil)
	legs := []leg{bottom, {}}
	legs[1] = proveLeg(assert, other, s, 2, feed(shape, legs, 1))

	assert.Error(solve(assert, inner, shape, legs, nil))
}

func TestNewShapeRejectsATreeThatDoesNotClose(t *testing.T) {
	assert := test.NewAssert(t)
	for _, levels := range [][]int{
		{},
		{4},
		{4, 2},
		{4, 0, 1},
		{9, 1},
		{2, 2},
	} {
		_, err := NewShape(levels)
		assert.Error(err, "levels %v", levels)
	}
}

func TestNewCircuitRejectsAnUnamortizedChain(t *testing.T) {
	assert := test.NewAssert(t)
	inner := newInnerSystem(assert)
	fixed, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](inner.vk)
	assert.NoError(err)

	_, err = NewCircuit(Shape{}, fixed, inner.ccs)
	assert.Error(err)
}
