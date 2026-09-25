package shared_test

import (
	"fmt"
	"math/big"
	"testing"

	customring "zolana/prover/circuits/spp_transaction/custom"
	defaultring "zolana/prover/circuits/spp_transaction/default"
	. "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func compileCached(t testing.TB, shape Shape) constraint.ConstraintSystem {
	t.Helper()
	c, err := defaultring.NewDefaultRingEddsaOnlyCircuit(shape)
	if err != nil {
		t.Fatal(err)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		t.Fatal(err)
	}
	return ccs
}

func checkCachedWitness(t testing.TB, ccs constraint.ConstraintSystem, c frontend.Circuit, wantValid bool) {
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

func cachedAssignment(t testing.TB, a *testAssignment, reads []int) *defaultring.DefaultRingEddsaOnlyCircuit {
	t.Helper()
	c := asDefaultRingEddsaOnly(a).(*defaultring.DefaultRingEddsaOnlyCircuit)
	c.CachedInputs = cacheReads(t, a, reads)
	refreshCachedHash(t, c)
	return c
}

func inputHash(t testing.TB, a *testAssignment, input int) *big.Int {
	t.Helper()
	return testUtxoHash(t, circuitFieldsToUtxo(a.Inputs[input].Utxo), a.inputTreeID(input))
}

func cacheReads(t testing.TB, a *testAssignment, reads []int) CachedInputs {
	t.Helper()
	n := len(a.Inputs)
	if len(reads) == 0 {
		return emptyCache(t, n)
	}
	c := emptyCache(t, n)
	hashes := zeroFields(n)
	for k, input := range reads {
		hashes[k] = inputHash(t, a, input)
		c.ReadHashes[k] = hashes[k]
		c.IsCached[input] = 1
		c.ReadIndex[input] = k
	}
	chain, err := protocol.RightHashChain4(hashes)
	c.TreeID = a.TreeSlots[0].ID
	c.ReadHashChain = spptest.MustHash(t, chain, err)
	return c
}

func rechain(t testing.TB, c *CachedInputs) {
	t.Helper()
	chain, err := protocol.RightHashChain4(spptest.ToBigInts(c.ReadHashes))
	c.ReadHashChain = spptest.MustHash(t, chain, err)
}

func refreshCachedHash(t testing.TB, c *defaultring.DefaultRingEddsaOnlyCircuit) {
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
		spptest.AsBigInt(c.CachedInputs.TreeID), spptest.AsBigInt(c.CachedInputs.ReadHashChain))
	h, err := protocol.HashChain4(fields)
	if err != nil {
		t.Fatal(err)
	}
	c.Public.PublicInputHash = h
}

func clearStatePaths(inputs []Input, reads []int) {
	for _, input := range reads {
		inputs[input].StatePathIndex = 0
		inputs[input].StatePathElements = spptest.ZeroVariables(StateTreeHeight)
	}
}

type cachedCase struct {
	name   string
	reads  []int
	valid  bool
	mutate func(*testing.T, *defaultring.DefaultRingEddsaOnlyCircuit)
}

func runCachedCases(t *testing.T, shape protocol.Shape, cases []cachedCase) {
	ccs := compileCached(t, Shape(shape))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := buildDefaultRingEddsaOnlyAssignment(t, shape)
			c := cachedAssignment(t, a, tc.reads)
			clearStatePaths(c.Private.Inputs, tc.reads)
			if tc.mutate != nil {
				tc.mutate(t, c)
			}
			refreshCachedHash(t, c)
			checkCachedWitness(t, ccs, c, tc.valid)
		})
	}
}

func TestCacheConstraints(t *testing.T) {
	runCachedCases(t, protocol.Shape{NInputs: 2, NOutputs: 2}, []cachedCase{
		{"all cached", []int{0, 1}, true, nil},
		{"list order independent of input order", []int{1, 0}, true, nil},
		{"only the second input cached", []int{1}, true, nil},
		{"only the first input cached", []int{0}, true, nil},
		{"a fully cached group needs no state root", []int{0, 1}, true, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Public.TreeSlots[0].UtxoRoot = 0
		}},
		{"an uncached input in a group without a state root", []int{1}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Public.TreeSlots[0].UtxoRoot = 0
		}},
		{"an uncached spend without a state root", nil, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Public.TreeSlots[0].UtxoRoot = 0
		}},
		{"cached spend requires nullifier root", []int{0, 1}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Public.TreeSlots[0].NullifierRoot = 0
		}},
		{"uncached input bad state path", []int{1}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Private.Inputs[0].StatePathElements[0] = 999
		}},
		{"empty selection", nil, true, nil},
		{"cached flag must be boolean", []int{0}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.CachedInputs.IsCached[0] = 2
		}},
		{"read index must name an entry", []int{0}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.CachedInputs.ReadIndex[0] = 2
		}},
		{"uncached read index must name an entry", []int{0}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.CachedInputs.ReadIndex[1] = 2
		}},
		{"read index points at another input's hash", []int{0, 1}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.CachedInputs.ReadIndex[0] = 1
		}},
		{"cached input cannot match zero padding", []int{0}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.CachedInputs.ReadIndex[0] = 1
		}},
		{"wrong cache tree", []int{0, 1}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) { c.CachedInputs.TreeID = 17 }},
		{"tree exceeds u16", []int{0, 1}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) { c.CachedInputs.TreeID = 65536 }},
		{"wrong read chain", []int{0, 1}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.CachedInputs.ReadHashChain = 123
		}},
		{"read list swapped without its indices", []int{0, 1}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			first, second := c.CachedInputs.ReadHashes[0], c.CachedInputs.ReadHashes[1]
			c.CachedInputs.ReadHashes[0], c.CachedInputs.ReadHashes[1] = second, first
			rechain(t, &c.CachedInputs)
		}},
		{"read list swapped with its indices", []int{0, 1}, true, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			first, second := c.CachedInputs.ReadHashes[0], c.CachedInputs.ReadHashes[1]
			c.CachedInputs.ReadHashes[0], c.CachedInputs.ReadHashes[1] = second, first
			c.CachedInputs.ReadIndex[0], c.CachedInputs.ReadIndex[1] = 1, 0
			rechain(t, &c.CachedInputs)
		}},
		{"unused list entries are allowed", []int{0}, true, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.CachedInputs.ReadHashes[1] = 77
			rechain(t, &c.CachedInputs)
		}},
		{"nullifier path still required", []int{0, 1}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Private.Inputs[0].NullifierLowPathElements[0] = 999
		}},
		{"nullifier derivation still required", []int{0, 1}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Public.Nullifiers[0] = 999
		}},
		{"owner authorization still required", []int{0, 1}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Private.InputOwnerPkHashes[0] = 999
		}},
		{"balance still required", []int{0, 1}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Public.PublicAssets[0] = c.Private.Inputs[0].Utxo.Asset
			c.Public.PublicAmounts[0] = 1
		}},
	})
}

func TestCachedInputsInterleaveWithTreeInputs(t *testing.T) {
	runCachedCases(t, protocol.Shape{NInputs: 5, NOutputs: 3}, []cachedCase{
		{"cached inputs at even positions, list in another order", []int{4, 0, 2}, true, nil},
		{"one cached input at the end", []int{4}, true, nil},
		{"one cached input in the middle", []int{2}, true, nil},
		{"all five cached in reverse", []int{4, 3, 2, 1, 0}, true, nil},
		{"interleaved uncached input keeps its inclusion proof", []int{4, 0, 2}, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Private.Inputs[3].StatePathElements[0] = 999
		}},
	})
}

func TestUncachedSpendCannotSkipInclusion(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	ccs := compileCached(t, Shape(shape))
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *testAssignment, *defaultring.DefaultRingEddsaOnlyCircuit)
	}{
		{"flag set against the default selection", func(t *testing.T, a *testAssignment, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.CachedInputs.IsCached[0] = 1
		}},
		{"hash listed but the published chain left at the default", func(t *testing.T, a *testAssignment, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.CachedInputs.IsCached[0] = 1
			c.CachedInputs.ReadHashes[0] = inputHash(t, a, 0)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := buildDefaultRingEddsaOnlyAssignment(t, shape)
			c := cachedAssignment(t, a, nil)
			checkCachedWitness(t, ccs, c, true)
			clearStatePaths(c.Private.Inputs, []int{0})
			tc.mutate(t, a, c)
			refreshCachedHash(t, c)
			checkCachedWitness(t, ccs, c, false)
		})
	}
}

func TestCachedInputMustBeOnTheCacheTree(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	ccs := compileCached(t, Shape(shape))
	a := buildDefaultRingEddsaOnlyAssignment(t, shape)
	moveInputToSlot(t, a, 1, 1)
	makeDefaultRing(t, a)
	c := cachedAssignment(t, a, []int{0})
	clearStatePaths(c.Private.Inputs, []int{0})
	checkCachedWitness(t, ccs, c, true)
	c = cachedAssignment(t, a, []int{0, 1})
	clearStatePaths(c.Private.Inputs, []int{0, 1})
	checkCachedWitness(t, ccs, c, false)
	c = cachedAssignment(t, a, []int{1})
	c.CachedInputs.TreeID = a.TreeSlots[1].ID
	refreshCachedHash(t, c)
	clearStatePaths(c.Private.Inputs, []int{1})
	checkCachedWitness(t, ccs, c, true)
}

func TestCachedDuplicateSpendsFail(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	ccs := compileCached(t, Shape(shape))
	for _, reads := range [][]int{{0}, {0, 1}} {
		t.Run(fmt.Sprintf("reads_%v", reads), func(t *testing.T) {
			inputs, outputs := defaultBalancedUtxos(t, shape)
			inputs[1].Amount = inputs[0].Amount
			for i := range outputs {
				outputs[i].Amount = inputs[0].Amount
			}
			a := buildDefaultRingEddsaOnlyAssignmentFromUtxos(t, shape, inputs, outputs)
			checkCachedWitness(t, ccs, cachedAssignment(t, a, reads), true)
			inputs[1] = inputs[0]
			a = buildDefaultRingEddsaOnlyAssignmentFromUtxos(t, shape, inputs, outputs)
			checkCachedWitness(t, ccs, cachedAssignment(t, a, reads), false)
		})
	}
	t.Run("two inputs reading one entry", func(t *testing.T) {
		inputs, outputs := defaultBalancedUtxos(t, shape)
		inputs[1] = inputs[0]
		for i := range outputs {
			outputs[i].Amount = inputs[0].Amount
		}
		a := buildDefaultRingEddsaOnlyAssignmentFromUtxos(t, shape, inputs, outputs)
		c := cachedAssignment(t, a, []int{0})
		c.CachedInputs.IsCached[1] = 1
		c.CachedInputs.ReadIndex[1] = 0
		refreshCachedHash(t, c)
		checkCachedWitness(t, ccs, c, false)
	})
}

func TestCachePublicHashBindsTheSelection(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	ccs := compileCached(t, Shape(shape))
	for _, field := range []string{"tree", "chain"} {
		t.Run(field, func(t *testing.T) {
			c := cachedAssignment(t, buildDefaultRingEddsaOnlyAssignment(t, shape), []int{1, 0})
			checkCachedWitness(t, ccs, c, true)
			original := c.CachedInputs
			switch field {
			case "tree":
				c.CachedInputs.TreeID = 17
			case "chain":
				c.CachedInputs.ReadHashChain = 123
			}
			refreshCachedHash(t, c)
			c.CachedInputs = original
			checkCachedWitness(t, ccs, c, false)
		})
	}
}

func TestCacheRejectsNonUtxos(t *testing.T) {
	shape := Shape{NInputs: 1, NOutputs: 2}
	ccs := compileCached(t, shape)
	checkCachedWitness(t, ccs, cachedAssignment(t, buildDefaultRingEddsaOnlyAssignment(t, protocol.Shape(shape)), []int{0}), true)
	for _, domain := range []string{"dummy", "address"} {
		t.Run(domain, func(t *testing.T) {
			a := buildDummyInputShield(t, 50)
			if domain == "address" {
				makeAddressSlot(t, a, 0, testSolanaPkField(t), spptest.Fe(123))
				finalizeAddressAssignment(t, a, false, true)
			}
			makeDefaultRing(t, a)
			checkCachedWitness(t, ccs, asDefaultRingEddsaOnly(a), true)
			checkCachedWitness(t, ccs, cachedAssignment(t, a, []int{0}), false)
			c := cachedAssignment(t, a, nil)
			c.CachedInputs.IsCached[0] = 1
			refreshCachedHash(t, c)
			checkCachedWitness(t, ccs, c, false)
			withoutRoot := cachedAssignment(t, a, nil)
			withoutRoot.Public.TreeSlots[0].UtxoRoot = 0
			refreshCachedHash(t, withoutRoot)
			checkCachedWitness(t, ccs, withoutRoot, true)
		})
	}
}

func TestCacheWidestShape(t *testing.T) {
	shape := protocol.Shape{NInputs: 36, NOutputs: 2}
	all := make([]int, 36)
	for k := range all {
		all[k] = 35 - k
	}
	runCachedCases(t, shape, []cachedCase{
		{"all cached in reverse", all, true, nil},
		{"sparse selection", []int{35, 7, 20}, true, nil},
	})
}

func TestCacheLayout(t *testing.T) {
	for _, shape := range []Shape{{NInputs: 0, NOutputs: 2}, {NInputs: 1, NOutputs: 0}} {
		c, err := defaultring.NewDefaultRingEddsaOnlyCircuit(shape)
		if err == nil {
			_, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
		}
		if err == nil {
			t.Fatalf("accepted invalid shape %+v", shape)
		}
	}
	for _, field := range []string{"state path", "read hashes", "cached flags", "read indices"} {
		t.Run(field, func(t *testing.T) {
			c, err := defaultring.NewDefaultRingEddsaOnlyCircuit(Shape{NInputs: 2, NOutputs: 2})
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "state path":
				c.Private.Inputs[0].StatePathElements = c.Private.Inputs[0].StatePathElements[:StateTreeHeight-1]
			case "read hashes":
				c.CachedInputs.ReadHashes = c.CachedInputs.ReadHashes[:1]
			case "cached flags":
				c.CachedInputs.IsCached = c.CachedInputs.IsCached[:1]
			case "read indices":
				c.CachedInputs.ReadIndex = c.CachedInputs.ReadIndex[:1]
			}
			if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c); err == nil {
				t.Fatal("accepted malformed layout")
			}
		})
	}
}

func emptyCache(t testing.TB, nInputs int) CachedInputs {
	t.Helper()
	chain, err := protocol.RightHashChain4(zeroFields(nInputs))
	c := NewCachedInputs(nInputs)
	c.TreeID = 0
	c.ReadHashChain = spptest.MustHash(t, chain, err)
	for k := 0; k < nInputs; k++ {
		c.ReadHashes[k] = 0
		c.IsCached[k] = 0
		c.ReadIndex[k] = 0
	}
	return c
}

func TestUncachedSpendSolvesWithTheDefaultSelection(t *testing.T) {
	shape := protocol.Shape{NInputs: 5, NOutputs: 3}
	ccs := compileCached(t, Shape(shape))
	a := buildDefaultRingEddsaOnlyAssignment(t, shape)
	checkCachedWitness(t, ccs, asDefaultRingEddsaOnly(a), true)
}

func TestCustomRingOptionalCache(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	for _, p256 := range []bool{false, true} {
		var circuit frontend.Circuit = MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
		if p256 {
			circuit = MustNewCustomRingP256Circuit(Shape(shape))
		}
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
		if err != nil {
			t.Fatal(err)
		}
		for _, reads := range [][]int{nil, {1}, {1, 0}} {
			t.Run(fmt.Sprintf("p256_%t/reads_%v", p256, reads), func(t *testing.T) {
				inputs, outputs := defaultBalancedUtxos(t, shape)
				for i := range inputs {
					inputs[i].RingProgramID = big.NewInt(0x5A)
				}
				a := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)
				owner := spptest.FixedP256Key(t, 11)
				if p256 {
					rewriteInputAsP256(t, a, 0, owner)
				}
				a.CachedInputs = cacheReads(t, a, reads)
				for _, input := range reads {
					a.Inputs[input].StatePathIndex = 0
					a.Inputs[input].StatePathElements = spptest.ZeroVariables(StateTreeHeight)
				}
				var assignment frontend.Circuit
				if p256 {
					authorization := authorizeP256(t, a, owner, owner)
					assignment = asCustomRingP256(a, authorization)
				} else {
					refreshPublicInputHash(t, a)
					assignment = asCustomRingEddsaOnly(a)
				}
				checkCachedWitness(t, ccs, assignment, true)
				switch c := assignment.(type) {
				case *customring.CustomRingEddsaOnlyCircuit:
					c.CachedInputs.ReadHashChain = 123
				case *customring.CustomRingP256Circuit:
					c.CachedInputs.ReadHashChain = 123
				}
				checkCachedWitness(t, ccs, assignment, false)
			})
		}
	}
}

func TestCacheChainRejectsTheLeftFold(t *testing.T) {
	shape := protocol.Shape{NInputs: 5, NOutputs: 3}
	ccs := compileCached(t, Shape(shape))
	reads := []int{0, 1, 2, 3, 4}
	a := buildDefaultRingEddsaOnlyAssignment(t, shape)
	c := cachedAssignment(t, a, reads)
	clearStatePaths(c.Private.Inputs, reads)
	checkCachedWitness(t, ccs, c, true)

	hashes := spptest.ToBigInts(c.CachedInputs.ReadHashes)
	left, err := protocol.HashChain4(hashes)
	if err != nil {
		t.Fatal(err)
	}
	right, err := protocol.RightHashChain4(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if left.Cmp(right) == 0 {
		t.Fatal("the two folds must differ at this width for the test to mean anything")
	}
	c.CachedInputs.ReadHashChain = left
	refreshCachedHash(t, c)
	checkCachedWitness(t, ccs, c, false)
}
