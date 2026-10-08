package emcurve

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/algebra/lattice"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256r1"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

var mergeScalar = new(big.Int).SetBytes([]byte("ephemeral scalar for the merge!!"))

func solveAgreeKey(t *testing.T, cs constraint.ConstraintSystem, assignment *agreeKeyCircuit, opts ...solver.Option) error {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	err = cs.IsSolved(witness, opts...)
	if err != nil && !strings.Contains(err.Error(), "is not satisfied") {
		t.Fatalf("expected a constraint failure, got: %v", err)
	}
	return err
}

func forgedScalarMulHint(forge func(*big.Int) *big.Int) solver.Hint {
	return func(q *big.Int, inputs, outputs []*big.Int) error {
		return emfield.Unwrap(q, inputs, outputs, func(_ *big.Int, _, in, out []*big.Int) error {
			var p secp256r1.G1Affine
			p.X.SetBigInt(in[0])
			p.Y.SetBigInt(in[1])
			p.ScalarMultiplication(&p, forge(new(big.Int).Mod(in[2], GroupOrder())))
			p.X.BigInt(out[0])
			p.Y.BigInt(out[1])
			return nil
		})
	}
}

func forgedDecompositionHint(scalar *big.Int) solver.Hint {
	return func(_ *big.Int, _, outputs []*big.Int) error {
		for _, out := range outputs {
			out.SetUint64(0)
		}
		if scalar == nil {
			return nil
		}
		res := lattice.NewReconstructor(GroupOrder()).RationalReconstruct(scalar)
		x, z := new(big.Int).Abs(res[0]), new(big.Int).Abs(res[1])
		if res[0].Sign()*res[1].Sign() > 0 {
			outputs[0].SetUint64(1)
		}
		for i := 0; i < halfScalarBits; i++ {
			outputs[1+i].SetUint64(uint64(x.Bit(i)))
			outputs[1+halfScalarBits+i].SetUint64(uint64(z.Bit(i)))
		}
		return nil
	}
}

func shiftedSlopeHint(slope func(p *big.Int, in []*big.Int) *big.Int) solver.Hint {
	return func(q *big.Int, inputs, outputs []*big.Int) error {
		return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
			out[0].Add(slope(p, in), big.NewInt(1)).Mod(out[0], p)
			return nil
		})
	}
}

func TestAgreeKeyRejectsTamperedOutputs(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &agreeKeyCircuit{NoLookups: noLookups})
		honest := agreeKeyWitness(t, mergeScalar, peerKey(t).PublicKey())
		if err := solveAgreeKey(t, cs, honest); err != nil {
			t.Fatalf("honest witness: %v", err)
		}
		for i := range honest.Expected {
			tampered := *honest
			tampered.Expected[i] = new(big.Int).Add(honest.Expected[i].(*big.Int), big.NewInt(1))
			if solveAgreeKey(t, cs, &tampered) == nil {
				t.Fatalf("output %d accepted after tampering", i)
			}
		}
	})
}

func TestAgreeKeyRejectsForgedHints(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &agreeKeyCircuit{NoLookups: noLookups})
		honest := agreeKeyWitness(t, mergeScalar, peerKey(t).PublicKey())
		chord := func(p *big.Int, in []*big.Int) *big.Int {
			yD := implicitDoubledY(p, in[0], in[1], in[2], in[3])
			return modRatio(p, new(big.Int).Sub(in[5], yD), new(big.Int).Sub(in[4], in[2]))
		}
		ratio := func(p *big.Int, in []*big.Int) *big.Int { return modRatio(p, in[0], in[1]) }
		forgeries := []struct {
			name string
			hint solver.Hint
			with solver.Hint
			also []solver.Option
		}{
			{"consistent ladder for another scalar", p256ScalarMulHint, forgedScalarMulHint(func(s *big.Int) *big.Int { return new(big.Int).Add(s, big.NewInt(1)) }),
				[]solver.Option{solver.OverrideHint(solver.GetHintID(p256DecomposeScalarHint), forgedDecompositionHint(new(big.Int).Add(mergeScalar, big.NewInt(1))))}},
			{"scalar mul result plus Q", p256ScalarMulHint, forgedScalarMulHint(func(s *big.Int) *big.Int { return new(big.Int).Add(s, big.NewInt(1)) }), nil},
			{"scalar mul result negated", p256ScalarMulHint, forgedScalarMulHint(func(s *big.Int) *big.Int { return new(big.Int).Sub(GroupOrder(), s) }), nil},
			{"zero decomposition", p256DecomposeScalarHint, forgedDecompositionHint(nil), nil},
			{"decomposition of another scalar", p256DecomposeScalarHint, forgedDecompositionHint(new(big.Int).Add(mergeScalar, big.NewInt(1))), nil},
			{"chord slope", p256ImplicitChordHint, shiftedSlopeHint(chord), nil},
			{"table slope", p256RatioHint, shiftedSlopeHint(ratio), nil},
			{"tangent slope", p256TangentHint, shiftedSlopeHint(func(p *big.Int, in []*big.Int) *big.Int {
				num := new(big.Int).Mul(in[0], in[0])
				num.Sub(num, big.NewInt(1)).Mul(num, big.NewInt(3))
				return modRatio(p, num, new(big.Int).Lsh(in[1], 1))
			}), nil},
			{"second slope", p256ImplicitSecondSlopeHint, shiftedSlopeHint(func(p *big.Int, in []*big.Int) *big.Int {
				yD := implicitDoubledY(p, in[0], in[1], in[2], in[3])
				return modRatio(p, new(big.Int).Lsh(yD, 1), new(big.Int).Sub(in[4], in[2]))
			}), nil},
			{"comb chain slope", p256CombChainHint, shiftedSlopeHint(func(p *big.Int, in []*big.Int) *big.Int {
				y := new(big.Int).Sub(in[2], in[1])
				y.Mul(y, in[0]).Sub(y, in[3])
				return modRatio(p, new(big.Int).Sub(in[5], y), new(big.Int).Sub(in[4], in[1]))
			}), nil},
			{"unified slope", p256UnifiedSlopeHint, shiftedSlopeHint(func(p *big.Int, in []*big.Int) *big.Int {
				return modRatio(p, new(big.Int).Sub(in[3], in[1]), new(big.Int).Sub(in[2], in[0]))
			}), nil},
			{"table point coordinates", p256AddHint, func(q *big.Int, inputs, outputs []*big.Int) error {
				if err := p256AddHint(q, inputs, outputs); err != nil {
					return err
				}
				outputs[len(outputs)-1].Xor(outputs[len(outputs)-1], big.NewInt(1))
				return nil
			}, nil},
			{"half-point tangent slope", p256HalfTangentHint, func(q *big.Int, inputs, outputs []*big.Int) error {
				if err := p256HalfTangentHint(q, inputs, outputs); err != nil {
					return err
				}
				outputs[0].Xor(outputs[0], big.NewInt(1))
				return nil
			}, nil},
			{"balanced slope limb", emfield.BalanceHint, func(q *big.Int, inputs, outputs []*big.Int) error {
				if err := emfield.BalanceHint(q, inputs, outputs); err != nil {
					return err
				}
				outputs[0].Xor(outputs[0], big.NewInt(1))
				return nil
			}, nil},
			{"x-coordinates claimed equal", p256XEqualHint, func(_ *big.Int, _, outputs []*big.Int) error {
				outputs[0].SetUint64(1)
				outputs[1].SetUint64(0)
				return nil
			}, nil},
			{"comb recoding of another scalar", p256CombRecodeHint, func(q *big.Int, inputs, outputs []*big.Int) error {
				shifted := []*big.Int{new(big.Int).Add(inputs[0], big.NewInt(1))}
				return p256CombRecodeHint(q, append(shifted, inputs[1:]...), outputs)
			}, nil},
			{"table row of another index", p256RowLookupHint, func(q *big.Int, inputs, outputs []*big.Int) error {
				moved := append([]*big.Int{new(big.Int).Xor(inputs[0], big.NewInt(1))}, inputs[1:]...)
				return p256RowLookupHint(q, moved, outputs)
			}, nil},
			{"table multiplicities", p256RowCountHint, func(q *big.Int, inputs, outputs []*big.Int) error {
				if err := p256RowCountHint(q, inputs, outputs); err != nil {
					return err
				}
				outputs[0].Add(outputs[0], big.NewInt(1))
				return nil
			}, nil},
			{"byte split", p256SplitLowBitsHint, func(_ *big.Int, inputs, outputs []*big.Int) error {
				n := uint(inputs[1].Uint64())
				outputs[0].Rsh(inputs[0], n).Sub(outputs[0], big.NewInt(1))
				outputs[1].And(inputs[0], new(big.Int).Sub(pow2(int(n)), big.NewInt(1))).Add(outputs[1], pow2(int(n)))
				return nil
			}, nil},
		}
		for _, f := range forgeries {
			if noLookups && isTableHint(f.hint) {
				continue
			}
			t.Run(f.name, func(t *testing.T) {
				called := false
				with := func(q *big.Int, inputs, outputs []*big.Int) error {
					called = true
					return f.with(q, inputs, outputs)
				}
				err := solveAgreeKey(t, cs, honest, append(f.also, solver.OverrideHint(solver.GetHintID(f.hint), with))...)
				if !called {
					t.Fatal("the forged hint never ran")
				}
				if err == nil {
					t.Fatal("forged hint accepted")
				}
			})
		}
	})
}

func smallCurvePoint(t *testing.T) (x, y *big.Int) {
	t.Helper()
	params := elliptic.P256().Params()
	for v := int64(1); v < 1000; v++ {
		x = big.NewInt(v)
		rhs := new(big.Int).Exp(x, big.NewInt(3), params.P)
		rhs.Sub(rhs, new(big.Int).Mul(x, big.NewInt(3))).Add(rhs, params.B).Mod(rhs, params.P)
		if y = new(big.Int).ModSqrt(rhs, params.P); y != nil {
			return x, y
		}
	}
	t.Fatal("no small point")
	return nil, nil
}

func TestAgreeKeyRejectsInvalidRecipients(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &agreeKeyCircuit{NoLookups: noLookups})
		params := elliptic.P256().Params()
		x, y := smallCurvePoint(t)
		uncompressed := append([]byte{4}, append(x.FillBytes(make([]byte, 32)), y.FillBytes(make([]byte, 32))...)...)
		peer, err := ecdh.P256().NewPublicKey(uncompressed)
		if err != nil {
			t.Fatalf("small point: %v", err)
		}
		honest := agreeKeyWitness(t, mergeScalar, peer)
		if err := solveAgreeKey(t, cs, honest); err != nil {
			t.Fatalf("honest witness: %v", err)
		}

		nonCanonical := *honest
		setBytes(nonCanonical.PublicKey[1:33], new(big.Int).Add(x, params.P).FillBytes(make([]byte, 32)))
		offCurve := *honest
		offCurve.PublicKey[64] = int(uncompressed[64] ^ 1)
		infinity := *honest
		setBytes(infinity.PublicKey[:], infinityPoint())
		wrongPrefix := *honest
		wrongPrefix.PublicKey[0] = 2
		for name, w := range map[string]*agreeKeyCircuit{
			"x plus p": &nonCanonical, "off curve": &offCurve, "infinity": &infinity, "prefix": &wrongPrefix,
		} {
			err := solveAgreeKey(t, cs, w)
			if err == nil {
				t.Fatalf("%s recipient accepted", name)
			}

		}
	})
}

type belowModulusCircuit struct {
	Limbs []frontend.Variable
}

func (c *belowModulusCircuit) Define(api frontend.API) error {
	cv := newCurve(api)
	cv.canonicalLimbs(cv.fp.FromLimbs(c.Limbs))
	return nil
}

func TestLimbsBelowModulus(t *testing.T) {
	cs := compile(t, &belowModulusCircuit{Limbs: make([]frontend.Variable, emfield.LookupLayout.NbLimbs)})
	p := emulated.P256Fp{}.Modulus()
	for _, row := range []struct {
		value  *big.Int
		accept bool
	}{
		{big.NewInt(0), true},
		{new(big.Int).Sub(p, big.NewInt(1)), true},
		{p, false},
		{new(big.Int).Sub(pow2(256), big.NewInt(1)), false},
	} {
		witness, err := frontend.NewWitness(&belowModulusCircuit{Limbs: fieldLimbValues(row.value)}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(witness); (err == nil) != row.accept {
			t.Fatalf("value %x: accept=%v err=%v", row.value, row.accept, err)
		}
	}
}

type distinctXCircuit struct {
	P, Q []frontend.Variable
}

func (c *distinctXCircuit) Define(api frontend.API) error {
	cv := newCurve(api)
	cv.assertDistinctX(cv.fp.FromLimbs(c.P), cv.fp.FromLimbs(c.Q))
	return nil
}

func fieldLimbValues(v *big.Int) []frontend.Variable {
	lay := emfield.LookupLayout
	out := make([]frontend.Variable, lay.NbLimbs)
	mask := new(big.Int).Sub(pow2(lay.LimbBits), big.NewInt(1))
	for i := range out {
		limb := new(big.Int).Rsh(v, uint(lay.LimbBits*i))
		out[i] = limb.And(limb, mask)
	}
	return out
}

func TestDistinctXGuard(t *testing.T) {
	n := emfield.LookupLayout.NbLimbs
	cs := compile(t, &distinctXCircuit{P: make([]frontend.Variable, n), Q: make([]frontend.Variable, n)})
	p := emulated.P256Fp{}.Modulus()
	x := big.NewInt(0x1234_5678)
	for _, row := range []struct {
		name   string
		p, q   *big.Int
		accept bool
	}{
		{"distinct", x, big.NewInt(0x1234_5679), true},
		{"equal", x, x, false},
		{"equal modulo p", x, new(big.Int).Add(x, p), false},
		{"equal modulo p swapped", new(big.Int).Add(x, p), x, false},
	} {
		witness, err := frontend.NewWitness(&distinctXCircuit{P: fieldLimbValues(row.p), Q: fieldLimbValues(row.q)}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(witness); (err == nil) != row.accept {
			t.Fatalf("%s: accept=%v err=%v", row.name, row.accept, err)
		}
	}
}
