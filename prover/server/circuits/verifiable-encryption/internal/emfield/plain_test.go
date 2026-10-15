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
	name string
	lay  Layout
}{{"plain", PlainLayout}, {"lookups", LookupLayout}}

func plainArithWitness(lay Layout, mod, a, b, c *big.Int) *plainArithCircuit {
	inv := new(big.Int).ModInverse(a, mod)
	r := new(big.Int).Sub(a, c)
	r.Mul(r, b).Mul(r, big.NewInt(3))
	r.Sub(r, new(big.Int).Mul(big.NewInt(2), new(big.Int).Mul(a, a)))
	r.Add(r, c)
	r.Sub(r, new(big.Int).Mul(inv, new(big.Int).Add(b, c)))
	r.Mod(r, mod)
	return &plainArithCircuit{Mod: mod, Lay: lay, A: plainLimbs(a), B: plainLimbs(b), C: plainLimbs(c), Expected: plainLimbs(r)}
}

func compilePlain(t *testing.T, mod *big.Int, lay Layout) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &plainArithCircuit{Mod: mod, Lay: lay})
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	if lay.Lookups {
		want = 1
	}
	if got := len(cs.GetCommitments().CommitmentIndexes()); got != want {
		t.Fatalf("layout %+v has %d commitments, want %d", lay, got, want)
	}
	return cs
}

func TestPlainLayoutFoldsOnlyTheSolinasPrime(t *testing.T) {
	if (&plainState{}).fold(8, 14) != nil {
		t.Fatal("empty state folded")
	}
	p := newPlainState(&Field{lay: PlainLayout, mod: p256P})
	n := newPlainState(&Field{lay: PlainLayout, mod: p256N})
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

func TestPlainArithmeticMatchesBigInt(t *testing.T) {
	for _, l := range layouts {
		for _, mod := range []*big.Int{p256P, p256N} {
			plainArithmeticMatchesBigInt(t, l.name, l.lay, mod)
		}
	}
}

func plainArithmeticMatchesBigInt(t *testing.T, name string, lay Layout, mod *big.Int) {
	cs := compilePlain(t, mod, lay)
	t.Logf("modulus %x... %s layout constraints %d wires %d", mod.Bytes()[:4], name, cs.GetNbConstraints(), cs.GetNbInternalVariables())
	for i := 0; i < 3; i++ {
		a, _ := rand.Int(rand.Reader, mod)
		b, _ := rand.Int(rand.Reader, mod)
		c, _ := rand.Int(rand.Reader, mod)
		if i == 0 {
			b.Sub(mod, big.NewInt(1))
			c.Sub(mod, big.NewInt(1))
		}
		w := plainArithWitness(lay, mod, a, b, c)
		if err := test.IsSolved(&plainArithCircuit{Mod: mod, Lay: lay}, w, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("test engine: %v", err)
		}
		witness, _ := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err := cs.IsSolved(witness); err != nil {
			t.Fatalf("compiled: %v", err)
		}
		bad := plainArithWitness(lay, mod, a, b, c)
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

func TestPlainCRTProductMatchesTheFold(t *testing.T) {
	q := ecc.BN254.ScalarField()
	s := newPlainState(&Field{lay: PlainLayout, mod: p256P})
	f := &Field{lay: PlainLayout, mod: p256P, plain: s}
	b := s.crtBasis(f, q)
	if b == nil {
		t.Fatal("the P-256 fold polynomial has no cheaper residue basis")
	}
	if len(b.forms) != 13 {
		t.Fatalf("%d bilinear products, expected 13 for factor degrees 2, 2 and 4", len(b.forms))
	}
	fp := polyReduce(poly{big.NewInt(-1), new(big.Int), new(big.Int), big.NewInt(1), new(big.Int), new(big.Int), big.NewInt(1), big.NewInt(-1), big.NewInt(1)}, q)
	if new(big.Int).Sub(new(big.Int).Add(new(big.Int).Add(pow2(256), pow2(192)), pow2(96)), new(big.Int).Add(pow2(224), big.NewInt(1))).Cmp(p256P) != 0 {
		t.Fatal("the fold polynomial does not evaluate to p at 2^32")
	}
	product := poly{big.NewInt(1)}
	degrees := map[int]int{}
	for _, g := range factorSquarefree(fp, q) {
		product = polyMul(product, g, q)
		degrees[polyDeg(g)]++
	}
	if len(polySub(product, fp, q)) != 0 {
		t.Fatal("the factors do not multiply back to the fold polynomial")
	}
	if degrees[2] != 2 || degrees[4] != 1 || len(degrees) != 2 {
		t.Fatalf("factor degrees %v, expected two quadratics and a quartic", degrees)
	}
	rows := s.fold(8, 14)
	bound := pow2(33)
	for trial := 0; trial < 64; trial++ {
		x, y := make([]*big.Int, 8), make([]*big.Int, 8)
		for i := range x {
			x[i], _ = rand.Int(rand.Reader, bound)
			y[i], _ = rand.Int(rand.Reader, bound)
			x[i].Sub(x[i], pow2(32))
			y[i].Sub(y[i], pow2(32))
		}
		want := make([]*big.Int, 8)
		for j := range want {
			want[j] = new(big.Int)
		}
		for i, c := range polyMulAbs(x, y) {
			for j := range want {
				want[j].Add(want[j], new(big.Int).Mul(c, rows[i][j]))
			}
		}
		got := b.foldedProduct(x, y, q)
		for j := range want {
			if new(big.Int).Mod(want[j], q).Cmp(got[j]) != 0 {
				t.Fatalf("trial %d coefficient %d: residue basis disagrees with the fold", trial, j)
			}
		}
	}
}

type plainCanonicalCircuit struct {
	Lay   Layout   `gnark:"-"`
	Mod   *big.Int `gnark:"-"`
	Limbs [8]frontend.Variable
}

func (c *plainCanonicalCircuit) Define(api frontend.API) error {
	mod := c.Mod
	if mod == nil {
		mod = p256P
	}
	f := NewFor(api, mod, c.Lay)
	f.AssertCanonical(f.FromLimbs(c.Limbs[:]))
	return nil
}

func TestPlainAssertCanonicalComparesLimbwise(t *testing.T) {
	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) { assertCanonicalComparesLimbwise(t, l.lay) })
	}
}

func assertCanonicalComparesLimbwise(t *testing.T, lay Layout) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &plainCanonicalCircuit{Lay: lay})
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
		w := &plainCanonicalCircuit{Lay: lay, Limbs: plainLimbs(v)}
		witness, _ := frontend.NewWitness(w, ecc.BN254.ScalarField())
		accept := v.Cmp(p256P) < 0
		if err := cs.IsSolved(witness); (err == nil) != accept {
			t.Fatalf("value %x: accept=%v err=%v", v, accept, err)
		}
		if err := test.IsSolved(&plainCanonicalCircuit{Lay: lay}, w, ecc.BN254.ScalarField()); (err == nil) != accept {
			t.Fatalf("test engine value %x: accept=%v err=%v", v, accept, err)
		}
	}
}

func TestPlainCheckHintForgeriesAreRejected(t *testing.T) {
	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) { plainCheckHintForgeriesAreRejected(t, l.lay) })
	}
}

func plainCheckHintForgeriesAreRejected(t *testing.T, lay Layout) {
	for _, mod := range []*big.Int{p256P, p256N} {
		cs := compilePlain(t, mod, lay)
		a, _ := new(big.Int).SetString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)
		b, _ := new(big.Int).SetString("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321", 16)
		w := plainArithWitness(lay, mod, new(big.Int).Mod(a, mod), new(big.Int).Mod(b, mod), new(big.Int).Sub(mod, big.NewInt(5)))
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

func TestCanonicalModulusGapRejectsForgery(t *testing.T) {
	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) {
			circuit := &plainCanonicalCircuit{Lay: l.lay, Mod: p256N}
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range []struct {
				value  *big.Int
				accept bool
			}{
				{big.NewInt(0), true},
				{new(big.Int).Sub(p256N, big.NewInt(1)), true},
				{p256N, false},
				{new(big.Int).Sub(pow2(256), big.NewInt(1)), false},
			} {
				witness, _ := frontend.NewWitness(&plainCanonicalCircuit{Lay: l.lay, Mod: p256N, Limbs: plainLimbs(row.value)}, ecc.BN254.ScalarField())
				if err := cs.IsSolved(witness); (err == nil) != row.accept {
					t.Fatalf("value %x: accept=%v err=%v", row.value, row.accept, err)
				}
			}
			forged := solver.OverrideHint(solver.GetHintID(modulusGapHint), func(q *big.Int, inputs, outputs []*big.Int) error {
				gap := new(big.Int).Sub(pow2(256), big.NewInt(1))
				rest := l.lay.writePieces(outputs, gap, l.lay.reducedWidths(256))
				rest[0].SetUint64(1)
				return nil
			})
			expectRejected(t, cs, &plainCanonicalCircuit{Lay: l.lay, Mod: p256N, Limbs: plainLimbs(p256N)}, forged)
		})
	}
}
