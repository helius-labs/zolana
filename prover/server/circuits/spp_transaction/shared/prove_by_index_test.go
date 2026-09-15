package shared_test

import (
	"fmt"
	"math/big"
	"testing"

	defaultring "zolana/prover/circuits/spp_transaction/default"
	. "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func compileByIndex(t testing.TB, shape Shape) constraint.ConstraintSystem {
	t.Helper()
	c, err := defaultring.NewDefaultRingEddsaOnlyByIndexCircuit(shape)
	if err != nil {
		t.Fatal(err)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		t.Fatal(err)
	}
	return ccs
}

func checkByIndexWitness(t testing.TB, ccs constraint.ConstraintSystem, c frontend.Circuit, wantValid bool) {
	t.Helper()
	w, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	err = ccs.IsSolved(w)
	if wantValid && err != nil {
		t.Fatalf("valid witness rejected: %v", err)
	}
	if !wantValid && err == nil {
		t.Fatal("invalid witness accepted")
	}
}

func byIndexAssignment(t testing.TB, a *testAssignment, bitmap uint64) *defaultring.DefaultRingEddsaOnlyByIndexCircuit {
	t.Helper()
	hashes := make([]*big.Int, len(a.Inputs))
	for i, in := range a.Inputs {
		hashes[i] = big.NewInt(0)
		if bitmap&(uint64(1)<<i) != 0 && spptest.AsBigInt(in.Utxo.Domain).Int64() == UtxoDomain {
			hashes[i] = testUtxoHash(t, circuitFieldsToUtxo(in.Utxo), a.inputTreeID(i))
		}
	}
	chain, err := protocol.HashChain4(hashes)
	if err != nil {
		t.Fatal(err)
	}
	c := &defaultring.DefaultRingEddsaOnlyByIndexCircuit{
		DefaultRingEddsaOnlyCircuit: *asDefaultRingEddsaOnly(a).(*defaultring.DefaultRingEddsaOnlyCircuit),
		ProveByIndex: defaultring.ProveByIndex{
			InputBitmap: new(big.Int).SetUint64(bitmap), TreeID: a.TreeSlots[0].ID, InputHashChain: chain,
		},
	}
	refreshByIndexHash(t, c)
	return c
}

// Independent native preimage, kept test-local until the prover integration phase.
func refreshByIndexHash(t testing.TB, c *defaultring.DefaultRingEddsaOnlyByIndexCircuit) {
	t.Helper()
	chain := func(values []frontend.Variable) *big.Int {
		h, err := protocol.HashChain4(spptest.ToBigInts(values))
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	p := c.Public
	signerChain, err := protocol.RightHashChain(spptest.ToBigInts(p.SignerPkHashes))
	if err != nil {
		t.Fatal(err)
	}
	fields := []*big.Int{
		chain(p.Nullifiers), chain(p.OutputHashes),
		spptest.MustTreeSlotsHashChain(t, treeSlotsToProtocol(p.TreeSlots)),
		spptest.AsBigInt(p.OutputTreeID), spptest.AsBigInt(p.PrivateTxHash), spptest.AsBigInt(p.ExternalDataHash),
	}
	for i := range p.PublicAssets {
		fields = append(fields, spptest.AsBigInt(p.PublicAssets[i]), spptest.AsBigInt(p.PublicAmounts[i]))
	}
	fields = append(fields, big.NewInt(0), signerChain, spptest.AsBigInt(p.InputFlags), chain(p.OutputOwnerPkHashes),
		spptest.AsBigInt(c.ProveByIndex.InputBitmap), spptest.AsBigInt(c.ProveByIndex.TreeID), spptest.AsBigInt(c.ProveByIndex.InputHashChain))
	h, err := protocol.HashChain4(fields)
	if err != nil {
		t.Fatal(err)
	}
	c.Public.PublicInputHash = h
}

func clearStatePaths(c *defaultring.DefaultRingEddsaOnlyByIndexCircuit, bitmap uint64) {
	for i := range c.Private.Inputs {
		if bitmap&(uint64(1)<<i) != 0 {
			c.Private.Inputs[i].StatePathIndex = 0
			c.Private.Inputs[i].StatePathElements = spptest.ZeroVariables(StateTreeHeight)
		}
	}
}

func TestProveByIndexConstraints(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	ccs := compileByIndex(t, Shape(shape))
	for _, tc := range []struct {
		name   string
		bitmap uint64
		valid  bool
		mutate func(*testing.T, *defaultring.DefaultRingEddsaOnlyByIndexCircuit)
	}{
		{"all indexed without state root", 3, true, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyByIndexCircuit) {
			c.Public.TreeSlots[0].UtxoRoot = 0
		}},
		{"mixed inclusion", 1, true, nil},
		{"unmarked bad state path", 1, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyByIndexCircuit) {
			c.Private.Inputs[1].StatePathElements[0] = 999
		}},
		{"unmarked requires state root", 1, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyByIndexCircuit) {
			c.Public.TreeSlots[0].UtxoRoot = 0
		}},
		{"empty bitmap", 0, false, nil},
		{"bitmap past input count", 5, false, nil},
		{"negative bitmap", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyByIndexCircuit) {
			c.ProveByIndex.InputBitmap = new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
		}},
		{"wrong receipt tree", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyByIndexCircuit) { c.ProveByIndex.TreeID = 17 }},
		{"tree exceeds u16", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyByIndexCircuit) { c.ProveByIndex.TreeID = 65536 }},
		{"wrong receipt commitments", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyByIndexCircuit) {
			c.ProveByIndex.InputHashChain = 123
		}},
		{"swapped receipt slots", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyByIndexCircuit) {
			hashes := []*big.Int{testUtxoHash(t, circuitFieldsToUtxo(c.Private.Inputs[1].Utxo), c.ProveByIndex.TreeID), testUtxoHash(t, circuitFieldsToUtxo(c.Private.Inputs[0].Utxo), c.ProveByIndex.TreeID)}
			h, err := protocol.HashChain4(hashes)
			if err != nil {
				t.Fatal(err)
			}
			c.ProveByIndex.InputHashChain = h
		}},
		{"unmasked unselected slot", 1, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyByIndexCircuit) {
			hashes := []*big.Int{testUtxoHash(t, circuitFieldsToUtxo(c.Private.Inputs[0].Utxo), c.ProveByIndex.TreeID), testUtxoHash(t, circuitFieldsToUtxo(c.Private.Inputs[1].Utxo), c.ProveByIndex.TreeID)}
			h, err := protocol.HashChain4(hashes)
			if err != nil {
				t.Fatal(err)
			}
			c.ProveByIndex.InputHashChain = h
		}},
		{"nullifier path still required", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyByIndexCircuit) {
			c.Private.Inputs[0].NullifierLowPathElements[0] = 999
		}},
		{"nullifier derivation still required", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyByIndexCircuit) { c.Public.Nullifiers[0] = 999 }},
		{"owner authorization still required", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyByIndexCircuit) {
			c.Private.InputOwnerPkHashes[0] = 999
		}},
		{"balance still required", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyByIndexCircuit) {
			c.Public.PublicAssets[0] = c.Private.Inputs[0].Utxo.Asset
			c.Public.PublicAmounts[0] = 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := buildDefaultRingEddsaOnlyAssignment(t, shape)
			c := byIndexAssignment(t, a, tc.bitmap)
			clearStatePaths(c, tc.bitmap)
			if tc.mutate != nil {
				tc.mutate(t, c)
			}
			// Rebind public mutations so rejection cannot be just a stale hash.
			refreshByIndexHash(t, c)
			checkByIndexWitness(t, ccs, c, tc.valid)
		})
	}

	t.Run("ordinary input may use another tree", func(t *testing.T) {
		a := buildDefaultRingEddsaOnlyAssignment(t, shape)
		moveInputToSlot(t, a, 1, 1)
		makeDefaultRing(t, a)
		c := byIndexAssignment(t, a, 1)
		clearStatePaths(c, 1)
		checkByIndexWitness(t, ccs, c, true)
		// The same otherwise-valid input cannot use this receipt's other tree.
		c = byIndexAssignment(t, a, 3)
		clearStatePaths(c, 3)
		checkByIndexWitness(t, ccs, c, false)
	})

	for _, bitmap := range []uint64{1, 3} {
		t.Run(fmt.Sprintf("duplicate nullifiers bitmap_%d", bitmap), func(t *testing.T) {
			inputs, outputs := defaultBalancedUtxos(t, shape)
			inputs[1].Amount = inputs[0].Amount
			for i := range outputs {
				outputs[i].Amount = inputs[0].Amount
			}
			a := buildDefaultRingEddsaOnlyAssignmentFromUtxos(t, shape, inputs, outputs)
			checkByIndexWitness(t, ccs, byIndexAssignment(t, a, bitmap), true)
			// Keep balance, ownership, paths and both transaction hashes valid,
			// but spend the same UTXO twice, including across inclusion modes.
			inputs[1] = inputs[0]
			a = buildDefaultRingEddsaOnlyAssignmentFromUtxos(t, shape, inputs, outputs)
			checkByIndexWitness(t, ccs, byIndexAssignment(t, a, bitmap), false)
		})
	}

	for _, field := range []string{"bitmap", "tree", "commitments"} {
		t.Run("public hash binds "+field, func(t *testing.T) {
			c := byIndexAssignment(t, buildDefaultRingEddsaOnlyAssignment(t, shape), 3)
			checkByIndexWitness(t, ccs, c, true)
			original := c.ProveByIndex
			switch field {
			case "bitmap":
				c.ProveByIndex.InputBitmap = 1
			case "tree":
				c.ProveByIndex.TreeID = 17
			case "commitments":
				c.ProveByIndex.InputHashChain = 123
			}
			refreshByIndexHash(t, c)
			c.ProveByIndex = original
			checkByIndexWitness(t, ccs, c, false)
		})
	}
}

func TestProveByIndexRejectsNonUtxos(t *testing.T) {
	shape := Shape{NInputs: 1, NOutputs: 2}
	ccs := compileByIndex(t, shape)
	checkByIndexWitness(t, ccs, byIndexAssignment(t, buildDefaultRingEddsaOnlyAssignment(t, protocol.Shape(shape)), 1), true)
	ordinary, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, MustNewDefaultRingEddsaOnlyCircuit(shape))
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"dummy", "address"} {
		t.Run(domain, func(t *testing.T) {
			a := buildDummyInputShield(t, 50)
			if domain == "address" {
				makeAddressSlot(t, a, 0, testSolanaPkField(t), spptest.Fe(123))
				finalizeAddressAssignment(t, a, false, true)
			}
			makeDefaultRing(t, a)
			checkByIndexWitness(t, ordinary, asDefaultRingEddsaOnly(a), true)
			checkByIndexWitness(t, ccs, byIndexAssignment(t, a, 1), false)
		})
	}
}

func TestProveByIndexCapacity(t *testing.T) {
	shape := protocol.Shape{NInputs: defaultring.ProveByIndexCapacity, NOutputs: 2}
	ccs := compileByIndex(t, Shape(shape))
	a := buildDefaultRingEddsaOnlyAssignment(t, shape)
	for _, bitmap := range []uint64{1 << 35, (1 << 36) - 1, 1 << 36} {
		t.Run(fmt.Sprintf("bitmap_%x", bitmap), func(t *testing.T) {
			c := byIndexAssignment(t, a, bitmap)
			clearStatePaths(c, bitmap)
			checkByIndexWitness(t, ccs, c, bitmap < 1<<36)
		})
	}
}

func TestProveByIndexLayout(t *testing.T) {
	for _, shape := range []Shape{{NInputs: 0, NOutputs: 2}, {NInputs: 1, NOutputs: 0}, {NInputs: 37, NOutputs: 2}} {
		if _, err := defaultring.NewDefaultRingEddsaOnlyByIndexCircuit(shape); err == nil {
			t.Fatalf("accepted invalid shape %+v", shape)
		}
	}
	c, err := defaultring.NewDefaultRingEddsaOnlyByIndexCircuit(Shape{NInputs: 1, NOutputs: 2})
	if err != nil {
		t.Fatal(err)
	}
	c.Private.Inputs[0].StatePathElements = c.Private.Inputs[0].StatePathElements[:StateTreeHeight-1]
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c); err == nil {
		t.Fatal("accepted malformed input layout")
	}
}
