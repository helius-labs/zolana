package shortchecker

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/internal/emfield"
)

type exactGuardCircuit struct {
	Mu, Lambda []frontend.Variable
	Layout     emfield.Layout `gnark:"-"`
	Baseline   bool           `gnark:"-"`
}

func (v *exactGuardCircuit) Define(api frontend.API) error {
	f := emfield.NewFor(api, prime(), v.Layout)
	widths := f.ReducedWidths()
	lo, hi := make([]*big.Int, len(widths)), make([]*big.Int, len(widths))
	for i, w := range widths {
		lo[i] = new(big.Int).Neg(pow2(w - 1))
		hi[i] = new(big.Int).Sub(pow2(w-1), big.NewInt(1))
		f.RangeChecker().Check(api.Add(v.Mu[i], pow2(w-1)), w)
		f.RangeChecker().Check(api.Add(v.Lambda[i], pow2(w-1)), w)
	}
	if !v.Baseline {
		c := &curve{api: api, fp: f, lay: v.Layout}
		c.assertLadderOutputDistinct(f.WithBounds(v.Lambda, lo, hi), f.WithBounds(v.Mu, lo, hi))
	}
	return nil
}

func TestExactSlopeGuard(t *testing.T) {
	q, p := ecc.BN254.ScalarField(), prime()
	for _, lay := range []emfield.Layout{
		{NbLimbs: 7, LimbBits: 37, PieceBits: 10, Lookups: true},
		{NbLimbs: 6, LimbBits: 43, PieceBits: 11, Lookups: true},
		{NbLimbs: 8, LimbBits: 32, PieceBits: 8, Lookups: false},
	} {
		t.Run(fmt.Sprintf("%dx%d/lookup%v", lay.NbLimbs, lay.LimbBits, lay.Lookups), func(t *testing.T) {
			blank := func(baseline bool) *exactGuardCircuit {
				return &exactGuardCircuit{Mu: make([]frontend.Variable, lay.NbLimbs), Lambda: make([]frontend.Variable, lay.NbLimbs), Layout: lay, Baseline: baseline}
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
				offset.Add(offset, new(big.Int).Lsh(pow2(widths[i]-1), uint(i*lay.LimbBits)))
			}
			minimum := new(big.Int).Neg(offset)
			maximum := new(big.Int).Sub(new(big.Int).Sub(pow2(255), offset), big.NewInt(1))
			fits := func(v *big.Int) bool { return v.Cmp(minimum) >= 0 && v.Cmp(maximum) <= 0 }
			pack := func(v *big.Int) []frontend.Variable {
				raw := new(big.Int).Add(v, offset)
				out := make([]frontend.Variable, len(widths))
				for i, w := range widths {
					part := new(big.Int).Rsh(new(big.Int).Set(raw), uint(i*lay.LimbBits))
					part.And(part, new(big.Int).Sub(pow2(w), big.NewInt(1)))
					out[i] = part.Sub(part, pow2(w-1))
				}
				return out
			}
			check := func(mu, lambda *big.Int, options ...solver.Option) bool {
				t.Helper()
				w := &exactGuardCircuit{Mu: pack(mu), Lambda: pack(lambda)}
				wit, err := frontend.NewWitness(w, q)
				if err != nil {
					t.Fatal(err)
				}
				return cs.IsSolved(wit, options...) == nil
			}
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
						want := mu.Sign() != 0 && new(big.Int).Mod(sum, p).Sign() != 0
						if check(mu, lambda) != want {
							t.Fatalf("k%d n%d epsilon%d mu%s lambda%s", k, n, epsilon, mu, lambda)
						}
						count++
					}
				}
			}
			for _, pair := range [][2]*big.Int{
				{q, big.NewInt(0)}, // mu is native zero but not field zero.
				{new(big.Int).Neg(q), big.NewInt(0)},
				{big.NewInt(1), new(big.Int).Rsh(new(big.Int).Sub(q, big.NewInt(1)), 1)}, // sum=q.
			} {
				if !check(pair[0], pair[1]) {
					t.Fatal("valid native alias rejected")
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
				bad := func(q *big.Int, in, out []*big.Int) error {
					if err := shortSlopeAliasHint(q, in, out); err != nil {
						return err
					}
					out[1].SetInt64(1)
					out[2].SetInt64(1)
					return nil
				}
				if check(mu, lambda, solver.OverrideHint(solver.GetHintID(shortSlopeAliasHint), bad)) {
					t.Fatal("forged nonzero alias quotient accepted")
				}
			}
			for index := 0; index < 3; index++ {
				called := false
				bad := func(q *big.Int, in, out []*big.Int) error {
					called = true
					if err := shortSlopeAliasHint(q, in, out); err != nil {
						return err
					}
					out[index].Add(out[index], big.NewInt(1))
					return nil
				}
				if check(q, big.NewInt(0), solver.OverrideHint(solver.GetHintID(shortSlopeAliasHint), bad)) || !called {
					t.Fatalf("forged alias output %d accepted or not exercised", index)
				}
			}
			t.Logf("checked %d bounded alias/neighbor pairs plus explicit zero and hostile-hint cases", count)
		})
	}
}
