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

func cachedAssignment(t testing.TB, a *testAssignment, bitmap uint64) *defaultring.DefaultRingEddsaOnlyCircuit {
	t.Helper()
	c := asDefaultRingEddsaOnly(a).(*defaultring.DefaultRingEddsaOnlyCircuit)
	c.CachedInputs = cacheFields(t, a, bitmap)
	refreshCachedHash(t, c)
	return c
}

func cacheFields(t testing.TB, a *testAssignment, bitmap uint64) CachedInputs {
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
	return CachedInputs{
		InputBitmap: new(big.Int).SetUint64(bitmap), TreeID: a.TreeSlots[0].ID, InputHashChain: chain,
	}
}

// Independent native preimage, kept test-local until the prover integration phase.
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
		spptest.AsBigInt(c.CachedInputs.InputBitmap), spptest.AsBigInt(c.CachedInputs.TreeID), spptest.AsBigInt(c.CachedInputs.InputHashChain))
	h, err := protocol.HashChain4(fields)
	if err != nil {
		t.Fatal(err)
	}
	c.Public.PublicInputHash = h
}

func clearStatePaths(c *defaultring.DefaultRingEddsaOnlyCircuit, bitmap uint64) {
	for i := range c.Private.Inputs {
		if bitmap&(uint64(1)<<i) != 0 {
			c.Private.Inputs[i].StatePathIndex = 0
			c.Private.Inputs[i].StatePathElements = spptest.ZeroVariables(StateTreeHeight)
		}
	}
}

func TestCacheConstraints(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	ccs := compileCached(t, Shape(shape))
	for _, tc := range []struct {
		name   string
		bitmap uint64
		valid  bool
		mutate func(*testing.T, *defaultring.DefaultRingEddsaOnlyCircuit)
	}{
		{"all cached without state root", 3, true, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Public.TreeSlots[0].UtxoRoot = 0
		}},
		{"mixed inclusion", 1, true, nil},
		{"unmarked bad state path", 1, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Private.Inputs[1].StatePathElements[0] = 999
		}},
		{"unmarked requires state root", 1, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Public.TreeSlots[0].UtxoRoot = 0
		}},
		{"empty bitmap", 0, true, nil},
		{"bitmap past input count", 5, false, nil},
		{"negative bitmap", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.CachedInputs.InputBitmap = new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
		}},
		{"wrong cache tree", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) { c.CachedInputs.TreeID = 17 }},
		{"tree exceeds u16", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) { c.CachedInputs.TreeID = 65536 }},
		{"wrong cache commitments", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.CachedInputs.InputHashChain = 123
		}},
		{"swapped cache slots", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			hashes := []*big.Int{testUtxoHash(t, circuitFieldsToUtxo(c.Private.Inputs[1].Utxo), c.CachedInputs.TreeID), testUtxoHash(t, circuitFieldsToUtxo(c.Private.Inputs[0].Utxo), c.CachedInputs.TreeID)}
			h, err := protocol.HashChain4(hashes)
			if err != nil {
				t.Fatal(err)
			}
			c.CachedInputs.InputHashChain = h
		}},
		{"unmasked unselected slot", 1, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			hashes := []*big.Int{testUtxoHash(t, circuitFieldsToUtxo(c.Private.Inputs[0].Utxo), c.CachedInputs.TreeID), testUtxoHash(t, circuitFieldsToUtxo(c.Private.Inputs[1].Utxo), c.CachedInputs.TreeID)}
			h, err := protocol.HashChain4(hashes)
			if err != nil {
				t.Fatal(err)
			}
			c.CachedInputs.InputHashChain = h
		}},
		{"nullifier path still required", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Private.Inputs[0].NullifierLowPathElements[0] = 999
		}},
		{"nullifier derivation still required", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) { c.Public.Nullifiers[0] = 999 }},
		{"owner authorization still required", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Private.InputOwnerPkHashes[0] = 999
		}},
		{"balance still required", 3, false, func(t *testing.T, c *defaultring.DefaultRingEddsaOnlyCircuit) {
			c.Public.PublicAssets[0] = c.Private.Inputs[0].Utxo.Asset
			c.Public.PublicAmounts[0] = 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := buildDefaultRingEddsaOnlyAssignment(t, shape)
			c := cachedAssignment(t, a, tc.bitmap)
			clearStatePaths(c, tc.bitmap)
			if tc.mutate != nil {
				tc.mutate(t, c)
			}
			// Rebind public mutations so rejection cannot be just a stale hash.
			refreshCachedHash(t, c)
			checkCachedWitness(t, ccs, c, tc.valid)
		})
	}

	t.Run("ordinary input may use another tree", func(t *testing.T) {
		a := buildDefaultRingEddsaOnlyAssignment(t, shape)
		moveInputToSlot(t, a, 1, 1)
		makeDefaultRing(t, a)
		c := cachedAssignment(t, a, 1)
		clearStatePaths(c, 1)
		checkCachedWitness(t, ccs, c, true)
		// The same otherwise-valid input cannot use this cache's other tree.
		c = cachedAssignment(t, a, 3)
		clearStatePaths(c, 3)
		checkCachedWitness(t, ccs, c, false)
	})

	for _, bitmap := range []uint64{1, 3} {
		t.Run(fmt.Sprintf("duplicate nullifiers bitmap_%d", bitmap), func(t *testing.T) {
			inputs, outputs := defaultBalancedUtxos(t, shape)
			inputs[1].Amount = inputs[0].Amount
			for i := range outputs {
				outputs[i].Amount = inputs[0].Amount
			}
			a := buildDefaultRingEddsaOnlyAssignmentFromUtxos(t, shape, inputs, outputs)
			checkCachedWitness(t, ccs, cachedAssignment(t, a, bitmap), true)
			// Keep balance, ownership, paths and both transaction hashes valid,
			// but spend the same UTXO twice, including across inclusion modes.
			inputs[1] = inputs[0]
			a = buildDefaultRingEddsaOnlyAssignmentFromUtxos(t, shape, inputs, outputs)
			checkCachedWitness(t, ccs, cachedAssignment(t, a, bitmap), false)
		})
	}

	for _, field := range []string{"bitmap", "tree", "commitments"} {
		t.Run("public hash binds "+field, func(t *testing.T) {
			c := cachedAssignment(t, buildDefaultRingEddsaOnlyAssignment(t, shape), 3)
			checkCachedWitness(t, ccs, c, true)
			original := c.CachedInputs
			switch field {
			case "bitmap":
				c.CachedInputs.InputBitmap = 1
			case "tree":
				c.CachedInputs.TreeID = 17
			case "commitments":
				c.CachedInputs.InputHashChain = 123
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
	checkCachedWitness(t, ccs, cachedAssignment(t, buildDefaultRingEddsaOnlyAssignment(t, protocol.Shape(shape)), 1), true)
	for _, domain := range []string{"dummy", "address"} {
		t.Run(domain, func(t *testing.T) {
			a := buildDummyInputShield(t, 50)
			if domain == "address" {
				makeAddressSlot(t, a, 0, testSolanaPkField(t), spptest.Fe(123))
				finalizeAddressAssignment(t, a, false, true)
			}
			makeDefaultRing(t, a)
			// The same circuit accepts the slot when no cache selects it.
			checkCachedWitness(t, ccs, asDefaultRingEddsaOnly(a), true)
			checkCachedWitness(t, ccs, cachedAssignment(t, a, 1), false)
		})
	}
}

func TestCacheCapacity(t *testing.T) {
	shape := protocol.Shape{NInputs: CacheCapacity, NOutputs: 2}
	ccs := compileCached(t, Shape(shape))
	a := buildDefaultRingEddsaOnlyAssignment(t, shape)
	for _, bitmap := range []uint64{1 << 35, (1 << 36) - 1, 1 << 36} {
		t.Run(fmt.Sprintf("bitmap_%x", bitmap), func(t *testing.T) {
			c := cachedAssignment(t, a, bitmap)
			clearStatePaths(c, bitmap)
			checkCachedWitness(t, ccs, c, bitmap < 1<<36)
		})
	}
}

func TestCacheLayout(t *testing.T) {
	for _, shape := range []Shape{{NInputs: 0, NOutputs: 2}, {NInputs: 1, NOutputs: 0}, {NInputs: 37, NOutputs: 2}} {
		c, err := defaultring.NewDefaultRingEddsaOnlyCircuit(shape)
		if err == nil {
			_, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
		}
		if err == nil {
			t.Fatalf("accepted invalid shape %+v", shape)
		}
	}
	c, err := defaultring.NewDefaultRingEddsaOnlyCircuit(Shape{NInputs: 1, NOutputs: 2})
	if err != nil {
		t.Fatal(err)
	}
	c.Private.Inputs[0].StatePathElements = c.Private.Inputs[0].StatePathElements[:StateTreeHeight-1]
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c); err == nil {
		t.Fatal("accepted malformed input layout")
	}
}

func emptyCache(t testing.TB, nInputs int) CachedInputs {
	t.Helper()
	chain, err := protocol.HashChain4(zeroFields(nInputs))
	return CachedInputs{InputBitmap: 0, TreeID: 0, InputHashChain: spptest.MustHash(t, chain, err)}
}

// Both owner-signed custom rails use the same cache binding as default transfers.
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
		for _, bitmap := range []uint64{0, 1, 3} {
			t.Run(fmt.Sprintf("p256_%t/bitmap_%d", p256, bitmap), func(t *testing.T) {
				inputs, outputs := defaultBalancedUtxos(t, shape)
				for i := range inputs {
					inputs[i].RingProgramID = big.NewInt(0x5A)
				}
				a := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)
				owner := spptest.FixedP256Key(t, 11)
				if p256 {
					rewriteInputAsP256(t, a, 0, owner)
				}
				a.CachedInputs = cacheFields(t, a, bitmap)
				// Only selected slots may omit their state paths; all keep nullifier proofs.
				for i := range a.Inputs {
					if bitmap&(uint64(1)<<i) != 0 {
						a.Inputs[i].StatePathIndex = 0
						a.Inputs[i].StatePathElements = spptest.ZeroVariables(StateTreeHeight)
					}
				}
				if bitmap == 3 {
					a.TreeSlots[0].UtxoRoot = 0
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
				// A supplied commitment chain cannot be changed without changing the public hash.
				switch c := assignment.(type) {
				case *customring.CustomRingEddsaOnlyCircuit:
					c.CachedInputs.InputHashChain = 123
				case *customring.CustomRingP256Circuit:
					c.CachedInputs.InputHashChain = 123
				}
				checkCachedWitness(t, ccs, assignment, false)
			})
		}
	}
}
