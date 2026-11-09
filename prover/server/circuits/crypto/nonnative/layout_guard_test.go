package nonnative

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type canonicalLayoutCircuit struct {
	Limbs   []frontend.Variable
	Modulus *big.Int `gnark:"-"`
	Layout  Layout   `gnark:"-"`
}

func (c *canonicalLayoutCircuit) Define(api frontend.API) error {
	f := NewFor(api, c.Modulus, c.Layout)
	f.AssertCanonical(f.Bounded(c.Limbs, f.ReducedWidths()))
	return nil
}

// Both layouts form canonical-check sums that can reach the native modulus.
func TestAssertCanonicalRejectsWrappingLayouts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		modulus *big.Int
		layout  Layout
	}{
		// A middle limb of m-1 that is not all ones forces the general fallback.
		{"general fallback", new(big.Int).Sub(edProjectionPrime, pow2(200)), Layout{NbLimbs: 3, LimbBits: 127, PieceBits: 10}},
		// A small low limb of m-1 makes the low-gap sum reach 2^254.
		{"low gap", new(big.Int).Add(new(big.Int).Mul(big.NewInt(3), pow2(253)), big.NewInt(7)), Layout{NbLimbs: 2, LimbBits: 253, PieceBits: 11}},
	} {
		circuit := &canonicalLayoutCircuit{Limbs: make([]frontend.Variable, tc.layout.NbLimbs), Modulus: tc.modulus, Layout: tc.layout}
		_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		if err == nil || !strings.Contains(err.Error(), "canonical check halves exceed the native field") {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

type oversizedLimbCircuit struct {
	Limbs [6]frontend.Variable
}

func (c *oversizedLimbCircuit) Define(api frontend.API) error {
	f := NewFor(api, edProjectionPrime, edProjectionLayout)
	f.Bounded(c.Limbs[:], []int{44, 43, 43, 43, 43, 40})
	return nil
}

// A lower limb wider than the layout spills past the recorded aggregate bound.
func TestBoundedRejectsOversizedLowerLimbs(t *testing.T) {
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &oversizedLimbCircuit{})
	if err == nil || !strings.Contains(err.Error(), "lower limb wider than the layout") {
		t.Fatalf("oversized limb: %v", err)
	}
}

type crossLayoutCircuit struct {
	Limbs [5]frontend.Variable
}

func (c *crossLayoutCircuit) Define(api frontend.API) error {
	producer := NewFor(api, edScalarOrder, Layout{NbLimbs: 5, LimbBits: 51, PieceBits: 17})
	consumer := NewFor(api, edScalarOrder, Layout{NbLimbs: 5, LimbBits: 53, PieceBits: 17})
	e := producer.Bounded(c.Limbs[:], []int{49, 50, 47, 50, 42})
	consumer.AssertZero(T(1, e))
	return nil
}

// A consumer reading another layout's limbs with its own radix drops carries.
func TestCrossLayoutElementsRejectCompilation(t *testing.T) {
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &crossLayoutCircuit{})
	if err == nil || !strings.Contains(err.Error(), "element layout differs from the field") {
		t.Fatalf("cross layout: %v", err)
	}
}

// Both layouts cover 2^255-19 with their lower limbs alone, leaving a zero-width limb.
func TestZeroWidthLimbLayoutsRejectCompilation(t *testing.T) {
	for _, layout := range []Layout{{NbLimbs: 4, LimbBits: 85, PieceBits: 11}, {NbLimbs: 5, LimbBits: 64, PieceBits: 11}} {
		circuit := &canonicalLayoutCircuit{Limbs: make([]frontend.Variable, layout.NbLimbs), Modulus: edProjectionPrime, Layout: layout}
		_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		if err == nil || !strings.Contains(err.Error(), "layout has a zero-width limb") {
			t.Errorf("%dx%d: %v", layout.NbLimbs, layout.LimbBits, err)
		}
	}
}
