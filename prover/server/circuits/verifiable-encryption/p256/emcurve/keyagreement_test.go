// Tested invariants and diagnostics:
//
//  1. Packed key agreement matches host ECDH with lookup and bit-based range checks.
//  2. Each altered packed output is rejected.
//  3. Forged decomposition, multiplication, slope, and lookup hints are rejected.
//  4. Malformed, noncanonical, and off-curve recipient encodings are rejected.
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
	"github.com/consensys/gnark/test"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

// Invariant 1: Packed key agreement matches host ECDH with lookup and bit-based range checks.
func TestAgreeKeyMatchesHostECDH(t *testing.T) {
	assert := test.NewAssert(t)
	peer := peerKey(t).PublicKey()
	n := GroupOrder()
	scalars := []*big.Int{
		new(big.Int).SetBytes([]byte("ephemeral scalar for the merge!!")),
		big.NewInt(2),
		new(big.Int).Sub(n, big.NewInt(2)),
		new(big.Int).Add(big.NewInt(0x1234_5678), n),
	}
	for _, s := range scalars {
		assert.NoError(test.IsSolved(&agreeKeyCircuit{}, agreeKeyWitness(t, s, peer), ecc.BN254.ScalarField()))
	}
}

// Invariant 1: Packed key agreement matches host ECDH with lookup and bit-based range checks.
func TestNoLookupAgreeKeyMatchesHostECDH(t *testing.T) {
	peer := peerKey(t).PublicKey()
	n := GroupOrder()
	cs := compile(t, &agreeKeyCircuit{NoLookups: true})
	for _, s := range []*big.Int{
		mergeScalar,
		big.NewInt(2),
		new(big.Int).Sub(n, big.NewInt(2)),
		new(big.Int).Add(big.NewInt(0x1234_5678), n),
	} {
		w := agreeKeyWitness(t, s, peer)
		if err := test.IsSolved(&agreeKeyCircuit{NoLookups: true}, w, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("test engine: %v", err)
		}
		if err := solveAgreeKey(t, cs, w); err != nil {
			t.Fatalf("compiled: %v", err)
		}
	}
}

// Invariant 2: Each altered packed output is rejected.
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

// Invariant 3: Forged decomposition, multiplication, slope, and lookup hints are rejected.
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

// Invariant 4: Malformed, noncanonical, and off-curve recipient encodings are rejected.
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

// Test circuits and shared helpers.

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

func fieldLimbValues(v *big.Int) []frontend.Variable {
	layout := emfield.LookupLayout
	out := make([]frontend.Variable, layout.NbLimbs)
	mask := new(big.Int).Sub(pow2(layout.LimbBits), big.NewInt(1))
	for i := range out {
		limb := new(big.Int).Rsh(v, uint(layout.LimbBits*i))
		out[i] = limb.And(limb, mask)
	}
	return out
}

type agreeKeyCircuit struct {
	NoLookups bool `gnark:"-"`
	Scalar    [32]frontend.Variable
	PublicKey [65]frontend.Variable
	Expected  [6]frontend.Variable `gnark:",public"`
}

func (c *agreeKeyCircuit) Define(api frontend.API) error {
	got := AgreeKeyFor(api, c.Scalar, c.PublicKey, !c.NoLookups)
	for i, v := range []frontend.Variable{got.RecipientLo, got.RecipientHi, got.EphemeralLo, got.EphemeralHi, got.SharedLo, got.SharedHi} {
		api.AssertIsEqual(v, c.Expected[i])
	}
	return nil
}

func packBytes(bytes []byte) (lo, hi *big.Int) {
	lo = new(big.Int).SetBytes(bytes[:31])
	hi = new(big.Int).SetBytes(bytes[31:])
	return lo, hi
}

func compressed(uncompressed []byte) []byte {
	x, y := elliptic.Unmarshal(elliptic.P256(), uncompressed)
	return elliptic.MarshalCompressed(elliptic.P256(), x, y)
}

func agreeKeyWitness(t *testing.T, scalar *big.Int, peer *ecdh.PublicKey) *agreeKeyCircuit {
	t.Helper()
	var w agreeKeyCircuit
	setBytes(w.Scalar[:], scalar.FillBytes(make([]byte, 32)))
	setBytes(w.PublicKey[:], peer.Bytes())
	reduced := new(big.Int).Mod(scalar, GroupOrder())
	key, err := ecdh.P256().NewPrivateKey(reduced.FillBytes(make([]byte, 32)))
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	shared, err := key.ECDH(peer)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	var values []*big.Int
	for _, bytes := range [][]byte{compressed(peer.Bytes()), compressed(key.PublicKey().Bytes()), shared} {
		lo, hi := packBytes(bytes)
		values = append(values, lo, hi)
	}
	for i, v := range values {
		w.Expected[i] = v
	}
	return &w
}
