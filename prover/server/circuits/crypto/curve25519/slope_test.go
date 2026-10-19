package curve25519

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/nonnative"
)

type slopeGuardCircuit struct {
	Mu, Lambda []frontend.Variable
	Layout     nonnative.Layout `gnark:"-"`
	Baseline   bool             `gnark:"-"`
}

func (v *slopeGuardCircuit) Define(api frontend.API) error {
	f := nonnative.NewFor(api, Prime(), v.Layout)
	widths := f.ReducedWidths()
	lo, hi := make([]*big.Int, len(widths)), make([]*big.Int, len(widths))
	for i, w := range widths {
		lo[i] = new(big.Int).Neg(Pow2(w - 1))
		hi[i] = new(big.Int).Sub(Pow2(w-1), big.NewInt(1))
		f.RangeChecker().Check(api.Add(v.Mu[i], Pow2(w-1)), w)
		f.RangeChecker().Check(api.Add(v.Lambda[i], Pow2(w-1)), w)
	}
	if !v.Baseline {
		AssertSlopeGuard(api, f, f.WithBounds(v.Lambda, lo, hi), f.WithBounds(v.Mu, lo, hi))
	}
	return nil
}

func TestSlopeGuard(t *testing.T) {
	q, p := ecc.BN254.ScalarField(), Prime()
	for _, lay := range []nonnative.Layout{
		{NbLimbs: 7, LimbBits: 37, PieceBits: 10},
		{NbLimbs: 6, LimbBits: 43, PieceBits: 11},
		{NbLimbs: 8, LimbBits: 32, PieceBits: 8},
	} {
		t.Run(fmt.Sprintf("%dx%d", lay.NbLimbs, lay.LimbBits), func(t *testing.T) {
			blank := func(baseline bool) *slopeGuardCircuit {
				return &slopeGuardCircuit{Mu: make([]frontend.Variable, lay.NbLimbs), Lambda: make([]frontend.Variable, lay.NbLimbs), Layout: lay, Baseline: baseline}
			}
			cs, err := frontend.Compile(q, r1cs.NewBuilder, blank(false))
			if err != nil {
				t.Fatal(err)
			}
			base, err := frontend.Compile(q, r1cs.NewBuilder, blank(true))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("guard adds %d constraints including its range-check costs", cs.GetNbConstraints()-base.GetNbConstraints())
			widths := make([]int, lay.NbLimbs)
			offset := new(big.Int)
			for i := range widths {
				widths[i] = min(lay.LimbBits, 255-i*lay.LimbBits)
				offset.Add(offset, new(big.Int).Lsh(Pow2(widths[i]-1), uint(i*lay.LimbBits)))
			}
			minimum := new(big.Int).Neg(offset)
			maximum := new(big.Int).Sub(new(big.Int).Sub(Pow2(255), offset), big.NewInt(1))
			fits := func(v *big.Int) bool { return v.Cmp(minimum) >= 0 && v.Cmp(maximum) <= 0 }
			pack := func(v *big.Int) []frontend.Variable {
				raw := new(big.Int).Add(v, offset)
				out := make([]frontend.Variable, len(widths))
				for i, w := range widths {
					part := new(big.Int).Rsh(new(big.Int).Set(raw), uint(i*lay.LimbBits))
					part.And(part, new(big.Int).Sub(Pow2(w), big.NewInt(1)))
					out[i] = part.Sub(part, Pow2(w-1))
				}
				return out
			}
			check := func(mu, lambda *big.Int) bool {
				t.Helper()
				w := &slopeGuardCircuit{Mu: pack(mu), Lambda: pack(lambda)}
				wit, err := frontend.NewWitness(w, q)
				if err != nil {
					t.Fatal(err)
				}
				return cs.IsSolved(wit) == nil
			}
			pp := new(big.Int).Mul(p, p)
			count := 0
			for k := int64(-1); k <= 1; k++ {
				for n := int64(-8); n <= 8; n++ {
					for epsilon := int64(-1); epsilon <= 1; epsilon++ {
						sum := new(big.Int).Mul(big.NewInt(k), p)
						sum.Add(sum, new(big.Int).Mul(big.NewInt(n), q)).Add(sum, big.NewInt(epsilon))
						lambda := new(big.Int).Div(sum, big.NewInt(3))
						mu := new(big.Int).Sub(sum, new(big.Int).Lsh(new(big.Int).Set(lambda), 1))
						if !fits(mu) || !fits(lambda) {
							continue
						}
						native := new(big.Int).Sub(new(big.Int).Mul(sum, sum), pp)
						native.Mul(native, sum).Mul(native, mu).Mod(native, q)
						if (mu.Sign() == 0 || new(big.Int).Mod(sum, p).Sign() == 0) && native.Sign() != 0 {
							t.Fatalf("zero modulo p escapes the native product, mu%s sum%s", mu, sum)
						}
						if check(mu, lambda) != (native.Sign() != 0) {
							t.Fatalf("k%d n%d epsilon%d mu%s lambda%s", k, n, epsilon, mu, lambda)
						}
						count++
					}
				}
			}
			if check(big.NewInt(0), big.NewInt(1)) {
				t.Fatal("zero mu accepted")
			}
			for _, sum := range []*big.Int{new(big.Int), p, new(big.Int).Neg(p)} {
				lambda := new(big.Int).Div(sum, big.NewInt(3))
				mu := new(big.Int).Sub(sum, new(big.Int).Lsh(new(big.Int).Set(lambda), 1))
				if sum.Sign() == 0 {
					mu.SetInt64(-2)
					lambda.SetInt64(1)
				}
				if check(mu, lambda) {
					t.Fatalf("slope sum %s accepted", sum)
				}
			}
			t.Logf("checked %d bounded alias/neighbor pairs plus explicit zero cases", count)
		})
	}
}
