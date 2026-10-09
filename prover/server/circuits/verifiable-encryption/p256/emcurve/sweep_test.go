// Tested invariants:
//
//  1. The ladder accepts every scalar k/m and -k/m with small k, m and random
//     scalars, and returns the host product.
//  2. Key agreement accepts the scalars 1/4, -1/4, 2/3 and -2/3, whose
//     decompositions used to trip the discarded correction guard.
package emcurve

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

type namedScalar struct {
	name string
	s    *big.Int
}

func ratioScalar(a, b int64) *big.Int {
	n := GroupOrder()
	r := new(big.Int).ModInverse(big.NewInt(b), n)
	return r.Mul(r, big.NewInt(a)).Mod(r, n)
}

func smallRatioScalars(limit int64, randoms int) []namedScalar {
	n := GroupOrder()
	var out []namedScalar
	for a := int64(1); a <= limit; a++ {
		for b := int64(1); b <= limit; b++ {
			if new(big.Int).GCD(nil, nil, big.NewInt(a), big.NewInt(b)).Int64() != 1 {
				continue
			}
			s := ratioScalar(a, b)
			out = append(out, namedScalar{fmt.Sprintf("%d/%d", a, b), s})
			out = append(out, namedScalar{fmt.Sprintf("-%d/%d", a, b), new(big.Int).Sub(n, s)})
		}
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < randoms; i++ {
		out = append(out, namedScalar{fmt.Sprintf("random%d", i), new(big.Int).Rand(rng, n)})
	}
	return out
}

// Invariant 1: The ladder accepts small ratios and random scalars.
func TestLadderAcceptsSmallRatioScalars(t *testing.T) {
	peer := peerKey(t).PublicKey().Bytes()
	px, py := elliptic.Unmarshal(elliptic.P256(), peer)
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &scalarMulCoordinatesCircuit{NoLookups: noLookups})
		for _, row := range smallRatioScalars(12, 16) {
			if row.s.Sign() == 0 {
				continue
			}
			w := &scalarMulCoordinatesCircuit{}
			setBytes(w.Scalar[:], row.s.FillBytes(make([]byte, 32)))
			setBytes(w.PublicKey[:], peer)
			x, y := elliptic.P256().ScalarMult(px, py, row.s.Bytes())
			setBytes(w.Result[:], elliptic.Marshal(elliptic.P256(), x, y))
			t.Run(row.name, func(t *testing.T) { assertCircuitResult(t, cs, w, true) })
		}
	})
}

// Invariant 2: Key agreement accepts the formerly rejected scalars.
func TestAgreeKeyAcceptsQuarterAndTwoThirds(t *testing.T) {
	n := GroupOrder()
	peer := peerKey(t).PublicKey()
	scalars := []*big.Int{ratioScalar(1, 4), ratioScalar(2, 3)}
	scalars = append(scalars, new(big.Int).Sub(n, scalars[0]), new(big.Int).Sub(n, scalars[1]))
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &agreeKeyCircuit{NoLookups: noLookups})
		for _, s := range scalars {
			w := agreeKeyWitness(t, s, peer)
			if err := test.IsSolved(&agreeKeyCircuit{NoLookups: noLookups}, w, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("test engine %v: %v", s, err)
			}
			if err := solveAgreeKey(t, cs, w); err != nil {
				t.Fatalf("compiled %v: %v", s, err)
			}
		}
	})
}
