// Tested invariants and diagnostics:
//
//  1. Generator multiplication reduces scalars and rejects infinity.
//  2. The final comb addition handles doubling and both scalar parities.
package emcurve

import (
	"crypto/ecdh"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

// Invariant 1: Generator multiplication reduces scalars and rejects infinity.
func TestGeneratorRefusesInfinityAndReducesScalars(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &generatorCircuit{NoLookups: noLookups})
		for _, row := range scalarRows(t) {
			t.Run(row.name, func(t *testing.T) {
				row.check(t, cs, row.generatorWitness(t))
			})
		}
	})
}

// Invariant 2: The final comb addition handles doubling and both scalar parities.
func TestGeneratorCompleteFinalAddition(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &generatorCircuit{NoLookups: noLookups})
		doublingScalar := doublingScalar(t, noLookups)
		for _, row := range []struct {
			s        *big.Int
			doubling bool
		}{
			{doublingScalar, true},
			{new(big.Int).Add(doublingScalar, big.NewInt(1)), false},
			{new(big.Int).Sub(GroupOrder(), doublingScalar), false},
		} {
			witness, err := frontend.NewWitness(generatorWitnessFor(t, row.s), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			hit := false
			record := solver.OverrideHint(solver.GetHintID(p256XEqualHint), func(q *big.Int, in, out []*big.Int) error {
				err := p256XEqualHint(q, in, out)
				hit = hit || out[0].Sign() != 0
				return err
			})
			if err := cs.IsSolved(witness, record); err != nil {
				t.Fatalf("s=%x: %v", row.s, err)
			}
			if hit != row.doubling {
				t.Fatalf("s=%x: doubling branch %v, expected %v", row.s, hit, row.doubling)
			}
			if noLookups {
				if err := test.IsSolved(&generatorCircuit{NoLookups: true}, generatorWitnessFor(t, row.s), ecc.BN254.ScalarField()); err != nil {
					t.Fatalf("test engine s=%x: %v", row.s, err)
				}
			}
		}
		witness, _ := frontend.NewWitness(generatorWitnessFor(t, doublingScalar), ecc.BN254.ScalarField())
		denied := solver.OverrideHint(solver.GetHintID(p256XEqualHint), func(_ *big.Int, _, out []*big.Int) error {
			out[0].SetUint64(0)
			out[1].SetUint64(1)
			return nil
		})
		if cs.IsSolved(witness, denied) == nil {
			t.Fatal("the doubling was accepted as a chord addition")
		}
	})
}

// Test circuits and shared helpers.

func doublingScalar(t *testing.T, noLookups bool) *big.Int {
	t.Helper()
	d := p256Comb(combWindowFor(emfield.LayoutFor(!noLookups)))
	n := GroupOrder()
	top := d.windowBits * (d.windowCount - 1)
	for digit := -(1<<d.topWindowBits - 1); digit < 1<<d.topWindowBits; digit += 2 {
		for b0 := uint(0); b0 < 2; b0++ {
			s := new(big.Int).Lsh(big.NewInt(int64(2*digit)), uint(top))
			s.Sub(s, big.NewInt(int64(2*(1-b0)))).Mod(s, n)
			if s.Bit(0) != b0 {
				continue
			}
			k := new(big.Int).Add(s, big.NewInt(int64(1-b0)))
			c := new(big.Int).Lsh(big.NewInt(1), uint(d.scalarBits))
			c.Sub(c, big.NewInt(1)).Add(c, k).Rsh(c, 1)
			j := new(big.Int).Rsh(c, uint(top)).Int64() & (1<<d.topWindowBits - 1)
			if int(2*j)-(1<<d.topWindowBits)+1 == digit {
				return s
			}
		}
	}
	t.Fatal("no scalar makes the final comb addition a doubling")
	return nil
}

func generatorWitnessFor(t *testing.T, s *big.Int) *generatorCircuit {
	t.Helper()
	var w generatorCircuit
	setBytes(w.Scalar[:], s.FillBytes(make([]byte, 32)))
	key, err := ecdh.P256().NewPrivateKey(s.FillBytes(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	setBytes(w.Point[:], key.PublicKey().Bytes())
	return &w
}
