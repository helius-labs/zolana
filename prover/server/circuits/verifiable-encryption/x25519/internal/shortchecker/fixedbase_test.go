package shortchecker

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
)

type generatorWindowCircuit struct {
	Scalar, PublicKey [32]frontend.Variable
	Window            int            `gnark:"-"`
	Layout            emfield.Layout `gnark:"-"`
}

type finalGeneratorAddCircuit struct {
	Output          []frontend.Variable
	Layout          emfield.Layout `gnark:"-"`
	OmitSumEquation bool           `gnark:"-"`
}

func (c *finalGeneratorAddCircuit) Define(api frontend.API) error {
	f := emfield.NewFor(api, prime(), c.Layout)
	window := 7
	if !c.Layout.Lookups {
		window = 10
	}
	tables := generatorWindowTables(window)
	last := tables[len(tables)-1]
	p := last[len(last)-1] // The equal-point final-addition boundary.
	a, b := coefficients(false)
	cv := &curve{api: api, fp: f, lay: c.Layout, a: f.Const(a), b: f.Const(b)}
	point := &point{X: f.Const(p.x), Y: f.Const(p.y)}
	var got *fpElement
	if c.OmitSumEquation {
		// Deliberately reproduce the unsound equal-point case with only
		// the chord equation. The forged output must satisfy this mutant.
		l := f.HintBalanced(baseFinalSlopeHint, 1, nil, point.X, point.Y, point.X, point.Y, cv.a)[0]
		f.AssertZeroProjected(T(1, l, f.Sub(point.X, point.X)))
		got = f.Lazy(T(1, l, l), T(-2, point.X))
	} else {
		got = cv.baseFinalAddX(point, point)
	}
	f.AssertZeroProjected(T(1, got), T(-1, f.FromLimbs(c.Output)))
	return nil
}

func TestFixedBaseFinalTangentGuard(t *testing.T) {
	for _, lay := range []emfield.Layout{{NbLimbs: 6, LimbBits: 43, PieceBits: 10, Lookups: true}, emfield.PlainLayout} {
		window := 7
		if !lay.Lookups {
			window = 10
		}
		tables := generatorWindowTables(window)
		last := tables[len(tables)-1]
		p := last[len(last)-1]
		a, _ := coefficients(false)
		honest := hostAdd(p, p, a).x
		forged := new(big.Int).Mod(new(big.Int).Mul(p.x, big.NewInt(-2)), prime())
		if forged.Cmp(honest) == 0 {
			t.Fatal("tangent forgery must change the output")
		}
		assignment := func(x *big.Int) *finalGeneratorAddCircuit {
			w := &finalGeneratorAddCircuit{Output: make([]frontend.Variable, lay.NbLimbs)}
			mask := new(big.Int).Sub(pow2(lay.LimbBits), big.NewInt(1))
			for i := range w.Output {
				w.Output[i] = new(big.Int).And(new(big.Int).Rsh(x, uint(i*lay.LimbBits)), mask)
			}
			return w
		}
		for _, mutant := range []bool{false, true} {
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &finalGeneratorAddCircuit{Output: make([]frontend.Variable, lay.NbLimbs), Layout: lay, OmitSumEquation: mutant})
			if err != nil {
				t.Fatal(err)
			}
			wit, err := frontend.NewWitness(assignment(honest), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.IsSolved(wit); err != nil {
				t.Fatal("honest tangent", err)
			}
			wit, err = frontend.NewWitness(assignment(forged), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			called := false
			zero := func(_ *big.Int, _, out []*big.Int) error {
				called = true
				for _, v := range out {
					v.SetInt64(0)
				}
				return nil
			}
			err = cs.IsSolved(wit, solver.OverrideHint(solver.GetHintID(baseFinalSlopeHint), zero))
			if !called || (err == nil) != mutant {
				t.Fatalf("lookup%v mutant%v: forged tangent acceptance%v hintcalled%v", lay.Lookups, mutant, err == nil, called)
			}
		}
	}
}

func (c *generatorWindowCircuit) Define(api frontend.API) error {
	f := emfield.NewFor(api, prime(), c.Layout)
	var bits []frontend.Variable
	for _, v := range c.Scalar {
		bits = append(bits, api.ToBinary(v, 8)...)
	}
	bits[254] = 1
	got := multiplyBaseWindow(api, f, bits[3:255], c.Window)
	f.AssertCanonical(got)
	var encoded []frontend.Variable
	for i, v := range got.Limbs() {
		encoded = append(encoded, api.ToBinary(v, f.ReducedWidths()[i])...)
	}
	encoded = append(encoded, 0)
	for i, b := range c.PublicKey {
		api.AssertIsEqual(b, api.FromBinary(encoded[8*i:8*i+8]...))
	}
	return nil
}

func TestGeneratorWindowSweep(t *testing.T) {
	if os.Getenv("X25519_BASE_WINDOW_SWEEP") != "1" {
		t.Skip("set X25519_BASE_WINDOW_SWEEP=1 for fixed-base experiment")
	}
	scalar := sha256.Sum256([]byte("generator window comparison"))
	sk, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	for _, lay := range []emfield.Layout{{NbLimbs: 6, LimbBits: 43, PieceBits: 10, Lookups: true}, emfield.PlainLayout} {
		for _, window := range []int{5, 6, 7, 8, 9, 10} {
			t.Run(fmt.Sprintf("lookup%v/window%d", lay.Lookups, window), func(t *testing.T) {
				cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &generatorWindowCircuit{Window: window, Layout: lay})
				if err != nil {
					t.Fatal(err)
				}
				w := new(generatorWindowCircuit)
				for i, b := range sk.PublicKey().Bytes() {
					w.Scalar[i], w.PublicKey[i] = scalar[i], b
				}
				wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				if err := cs.IsSolved(wit); err != nil {
					t.Fatal(err)
				}
				t.Logf("constraints %d", cs.GetNbConstraints())
			})
		}
	}
}
