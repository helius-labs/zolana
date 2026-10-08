// Tested invariants and diagnostics:
//
//  1. Modulus folding is enabled for the supported coordinate prime, not the scalar
//     order.
//  2. Arithmetic matches big.Int calculations.
//  3. Forged modular-check hint outputs are rejected.
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

// Invariant 1: Modulus folding is enabled for the supported coordinate prime, not the scalar order.
func TestPlainLayoutFoldsOnlyTheSolinasPrime(t *testing.T) {
	if (&arithmeticState{}).fold(8, 14) != nil {
		t.Fatal("empty state folded")
	}
	p := newArithmeticState(&Field{layout: PlainLayout, mod: p256P})
	n := newArithmeticState(&Field{layout: PlainLayout, mod: p256N})
	if p.foldDigits == nil || n.foldDigits != nil {
		t.Fatalf("fold digits p %v n %v", p.foldDigits, n.foldDigits)
	}
	rows := p.fold(8, 14)
	for i, row := range rows {
		v := new(big.Int)
		for j := len(row) - 1; j >= 0; j-- {
			v.Lsh(v, 32).Add(v, row[j])
		}
		want := new(big.Int).Mod(pow2(32*i), p256P)
		if v.Mod(v, p256P).Cmp(want) != 0 {
			t.Fatalf("fold row %d is not 2^(32i) mod p", i)
		}
	}
}

// Invariant 2: Arithmetic matches big.Int calculations.
func TestPlainArithmeticMatchesBigInt(t *testing.T) {
	for _, l := range layouts {
		for _, mod := range []*big.Int{p256P, p256N} {
			plainArithmeticMatchesBigInt(t, l.name, l.layout, mod)
		}
	}
}

// Invariant 3: Forged modular-check hint outputs are rejected.
func TestPlainCheckHintForgeriesAreRejected(t *testing.T) {
	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) { plainCheckHintForgeriesAreRejected(t, l.layout) })
	}
}

// Test circuits and shared helpers.

var p256N, _ = new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

type plainArithCircuit struct {
	Mod      *big.Int `gnark:"-"`
	Lay      Layout   `gnark:"-"`
	A, B, C  [8]frontend.Variable
	Expected [8]frontend.Variable `gnark:",public"`
}

func (c *plainArithCircuit) Define(api frontend.API) error {
	f := NewFor(api, c.Mod, c.Lay)
	a, b, cc := f.FromLimbs(c.A[:]), f.FromLimbs(c.B[:]), f.FromLimbs(c.C[:])
	inv := f.Hint(inverseHint, 1, nil, a)[0]
	f.AssertZero(T(1, inv, a), T(-1, f.Const(big.NewInt(1))))
	sum := f.Sub(a, cc)
	r := f.Eval(T(3, sum, b), T(-2, a, a), T(1, cc), T(-1, inv, f.Add(b, cc)))
	f.AssertZero(T(1, r), T(-1, f.Reduced(c.Expected[:])))
	for i, l := range r.Limbs() {
		api.AssertIsEqual(l, c.Expected[i])
	}
	f.AssertCanonical(r)
	return nil
}

func plainLimbs(v *big.Int) [8]frontend.Variable {
	var out [8]frontend.Variable
	for i, l := range PlainLayout.decompose(v, 8) {
		out[i] = l
	}
	return out
}

var layouts = []struct {
	name   string
	layout Layout
}{{"plain", PlainLayout}, {"lookups", LookupLayout}}

func plainArithWitness(layout Layout, mod, a, b, c *big.Int) *plainArithCircuit {
	inv := new(big.Int).ModInverse(a, mod)
	r := new(big.Int).Sub(a, c)
	r.Mul(r, b).Mul(r, big.NewInt(3))
	r.Sub(r, new(big.Int).Mul(big.NewInt(2), new(big.Int).Mul(a, a)))
	r.Add(r, c)
	r.Sub(r, new(big.Int).Mul(inv, new(big.Int).Add(b, c)))
	r.Mod(r, mod)
	return &plainArithCircuit{Mod: mod, Lay: layout, A: plainLimbs(a), B: plainLimbs(b), C: plainLimbs(c), Expected: plainLimbs(r)}
}

func compilePlain(t *testing.T, mod *big.Int, layout Layout) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &plainArithCircuit{Mod: mod, Lay: layout})
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	if layout.Lookups {
		want = 1
	}
	if got := len(cs.GetCommitments().CommitmentIndexes()); got != want {
		t.Fatalf("layout %+v has %d commitments, want %d", layout, got, want)
	}
	return cs
}

func plainArithmeticMatchesBigInt(t *testing.T, name string, layout Layout, mod *big.Int) {
	cs := compilePlain(t, mod, layout)
	t.Logf("modulus %x... %s layout constraints %d wires %d", mod.Bytes()[:4], name, cs.GetNbConstraints(), cs.GetNbInternalVariables())
	for i := 0; i < 3; i++ {
		a, _ := rand.Int(rand.Reader, mod)
		b, _ := rand.Int(rand.Reader, mod)
		c, _ := rand.Int(rand.Reader, mod)
		if i == 0 {
			b.Sub(mod, big.NewInt(1))
			c.Sub(mod, big.NewInt(1))
		}
		w := plainArithWitness(layout, mod, a, b, c)
		if err := test.IsSolved(&plainArithCircuit{Mod: mod, Lay: layout}, w, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("test engine: %v", err)
		}
		witness, _ := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err := cs.IsSolved(witness); err != nil {
			t.Fatalf("compiled: %v", err)
		}
		bad := plainArithWitness(layout, mod, a, b, c)
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

func assertCanonicalComparesLimbwise(t *testing.T, layout Layout) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &plainCanonicalCircuit{Lay: layout})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("canonical check over range-checked limbs: %d constraints", cs.GetNbConstraints())
	fromLimbs := func(limbs ...uint64) *big.Int {
		v := new(big.Int)
		for _, l := range limbs {
			v.Lsh(v, 32).Or(v, new(big.Int).SetUint64(l))
		}
		return v
	}
	const ones = 0xffffffff
	values := []*big.Int{
		big.NewInt(0),
		new(big.Int).Sub(p256P, big.NewInt(1)),
		p256P,
		new(big.Int).Add(p256P, big.NewInt(1)),
		new(big.Int).Sub(pow2(256), big.NewInt(1)),
		fromLimbs(ones, 0, ones, ones, ones, ones, ones, ones),
		fromLimbs(ones, 1, 1, 0, 0, 0, 0, 0),
		fromLimbs(ones, 1, 0, 0, 1, 0, 0, 0),
		fromLimbs(ones, 2, 0, 0, 0, 0, 0, 0),
		fromLimbs(ones, 1, 0, 0, 0, ones-1, ones, ones),
		fromLimbs(ones, 1, 0, 0, 0, ones, ones-1, ones),
		fromLimbs(ones-1, ones, ones, ones, ones, ones, ones, ones),
	}
	for i := 0; i < 32; i++ {
		v, _ := rand.Int(rand.Reader, pow2(256))
		values = append(values, v)
	}
	for _, v := range values {
		w := &plainCanonicalCircuit{Lay: layout, Limbs: plainLimbs(v)}
		witness, _ := frontend.NewWitness(w, ecc.BN254.ScalarField())
		accept := v.Cmp(p256P) < 0
		if err := cs.IsSolved(witness); (err == nil) != accept {
			t.Fatalf("value %x: accept=%v err=%v", v, accept, err)
		}
		if err := test.IsSolved(&plainCanonicalCircuit{Lay: layout}, w, ecc.BN254.ScalarField()); (err == nil) != accept {
			t.Fatalf("test engine value %x: accept=%v err=%v", v, accept, err)
		}
	}
}

func plainCheckHintForgeriesAreRejected(t *testing.T, layout Layout) {
	for _, mod := range []*big.Int{p256P, p256N} {
		cs := compilePlain(t, mod, layout)
		a, _ := new(big.Int).SetString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)
		b, _ := new(big.Int).SetString("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321", 16)
		w := plainArithWitness(layout, mod, new(big.Int).Mod(a, mod), new(big.Int).Mod(b, mod), new(big.Int).Sub(mod, big.NewInt(5)))
		forgeries := map[string]func(q *big.Int, outputs []*big.Int){
			"remainder plus modulus in the top limb": func(q *big.Int, outputs []*big.Int) {
				outputs[0].Add(outputs[0], big.NewInt(1))
			},
			"remainder shifted across a limb": func(q *big.Int, outputs []*big.Int) {
				if len(outputs) < 2 {
					return
				}
				outputs[0].Add(outputs[0], pow2(32))
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
