package emfield

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

// Modulus folding is enabled for the coordinate prime, not the scalar order.
func TestLayoutFoldsOnlyTheSolinasPrime(t *testing.T) {
	if (&arithmeticState{}).fold(6, 10) != nil {
		t.Fatal("empty state folded")
	}
	p := newArithmeticState(&Field{layout: edProjectionLayout, mod: edProjectionPrime})
	n := newArithmeticState(&Field{layout: edProjectionLayout, mod: edScalarOrder})
	if p.foldDigits == nil || n.foldDigits != nil {
		t.Fatalf("fold digits p %v n %v", p.foldDigits, n.foldDigits)
	}
	for i, row := range p.fold(6, 10) {
		v := new(big.Int)
		for j := len(row) - 1; j >= 0; j-- {
			v.Lsh(v, 43).Add(v, row[j])
		}
		if v.Mod(v, edProjectionPrime).Cmp(new(big.Int).Mod(pow2(43*i), edProjectionPrime)) != 0 {
			t.Fatalf("fold row %d is not 2^(43i) mod p", i)
		}
	}
}

func TestPlainArithmeticMatchesBigInt(t *testing.T) {
	for _, mod := range []*big.Int{edProjectionPrime, edScalarOrder} {
		cs := compilePlain(t, mod)
		t.Logf("modulus %x... constraints %d wires %d", mod.Bytes()[:4], cs.GetNbConstraints(), cs.GetNbInternalVariables())
		for i := 0; i < 3; i++ {
			a, _ := rand.Int(rand.Reader, mod)
			b, _ := rand.Int(rand.Reader, mod)
			c, _ := rand.Int(rand.Reader, mod)
			if i == 0 {
				b.Sub(mod, big.NewInt(1))
				c.Sub(mod, big.NewInt(1))
			}
			w := plainArithWitness(mod, a, b, c)
			if err := test.IsSolved(&plainArithCircuit{Mod: mod}, w, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("test engine: %v", err)
			}
			witness, _ := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err := cs.IsSolved(witness); err != nil {
				t.Fatalf("compiled: %v", err)
			}
			bad := plainArithWitness(mod, a, b, c)
			bad.Expected[0] = new(big.Int).Add(bad.Expected[0].(*big.Int), big.NewInt(1))
			expectRejected(t, cs, bad)
			expectRejected(t, cs, w, solver.OverrideHint(solver.GetHintID(inverseHint), func(q *big.Int, inputs, outputs []*big.Int) error {
				return Unwrap(q, inputs, outputs, func(m *big.Int, _, in, out []*big.Int) error {
					out[0].ModInverse(in[0], m)
					out[0].Add(out[0], big.NewInt(1))
					return nil
				})
			}))
		}
	}
}

func TestPlainCheckHintForgeriesAreRejected(t *testing.T) {
	for _, mod := range []*big.Int{edProjectionPrime, edScalarOrder} {
		cs := compilePlain(t, mod)
		a, _ := new(big.Int).SetString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)
		b, _ := new(big.Int).SetString("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321", 16)
		w := plainArithWitness(mod, new(big.Int).Mod(a, mod), new(big.Int).Mod(b, mod), new(big.Int).Sub(mod, big.NewInt(5)))
		forgeries := map[string]func(q *big.Int, outputs []*big.Int){
			"remainder plus one": func(q *big.Int, outputs []*big.Int) {
				outputs[0].Add(outputs[0], big.NewInt(1))
			},
			"remainder shifted across a piece": func(q *big.Int, outputs []*big.Int) {
				if len(outputs) < 2 {
					return
				}
				outputs[0].Add(outputs[0], pow2(edProjectionLayout.PieceBits))
				outputs[1].Sub(outputs[1], big.NewInt(1)).Mod(outputs[1], q)
			},
			"last output wrapped": func(q *big.Int, outputs []*big.Int) {
				last := outputs[len(outputs)-1]
				last.Sub(last, big.NewInt(1)).Mod(last, q)
			},
		}
		for name, forge := range forgeries {
			t.Run(name, func(t *testing.T) {
				expectRejected(t, cs, w, solver.OverrideHint(solver.GetHintID(PlainCheckHint), func(q *big.Int, inputs, outputs []*big.Int) error {
					if err := PlainCheckHint(q, inputs, outputs); err != nil {
						return err
					}
					forge(q, outputs)
					return nil
				}))
			})
		}
	}
}

type plainArithCircuit struct {
	Mod      *big.Int `gnark:"-"`
	A, B, C  [6]frontend.Variable
	Expected [6]frontend.Variable `gnark:",public"`
}

func (c *plainArithCircuit) Define(api frontend.API) error {
	f := NewFor(api, c.Mod, edProjectionLayout)
	a, b, cc := fromLimbs(f, c.A[:]), fromLimbs(f, c.B[:]), fromLimbs(f, c.C[:])
	inv := f.Hint(inverseHint, 1, nil, a)[0]
	f.AssertZero(T(1, inv, a), T(-1, f.Const(big.NewInt(1))))
	sum := f.Sub(a, cc)
	r := f.Eval(T(3, sum, b), T(-2, a, a), T(1, cc), T(-1, inv, f.Add(b, cc)))
	f.AssertZero(T(1, r), T(-1, f.Bounded(c.Expected[:], f.widths)))
	for i, l := range r.Limbs() {
		api.AssertIsEqual(l, c.Expected[i])
	}
	f.AssertCanonical(r)
	return nil
}

func plainArithWitness(mod, a, b, c *big.Int) *plainArithCircuit {
	inv := new(big.Int).ModInverse(a, mod)
	r := new(big.Int).Sub(a, c)
	r.Mul(r, b).Mul(r, big.NewInt(3))
	r.Sub(r, new(big.Int).Mul(big.NewInt(2), new(big.Int).Mul(a, a)))
	r.Add(r, c)
	r.Sub(r, new(big.Int).Mul(inv, new(big.Int).Add(b, c)))
	r.Mod(r, mod)
	return &plainArithCircuit{Mod: mod, A: edLimbs(a), B: edLimbs(b), C: edLimbs(c), Expected: edLimbs(r)}
}

func compilePlain(t *testing.T, mod *big.Int) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &plainArithCircuit{Mod: mod})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(cs.GetCommitments().CommitmentIndexes()); got != 1 {
		t.Fatalf("%d commitments, want 1", got)
	}
	return cs
}
