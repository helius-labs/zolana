// Tested invariants and diagnostics:
//
//  1. Supported honest signatures match the host verifier.
//  2. Invalid signatures and malformed inputs are rejected.
//  3. ECDSA accepts exceptional signature scalars and a zero message digest.
//  4. Forged reports and mutated hints cannot satisfy signature verification.
//  5. The verification x-coordinate is compared modulo the group order, including
//     wraparound; valid additions also handle native-modulus X collisions.
//  6. Diagnostic: signature constraint counts are recorded for both range-check
//     modes.
//  7. ECDSA rejects source limbs wider than the native field.
package emcurve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256r1"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

// Invariant 1: Supported honest signatures match the host verifier.
func TestECDSAAcceptsHonestSignatures(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &ecdsaCircuit{NoLookups: noLookups})
		n := GroupOrder()
		for i, message := range []string{"spend", "another spend", "a third spend"} {
			v := signedVector(t, signingKey(t), message)
			twin := v.with(func(w *ecdsaVector) { w.s = new(big.Int).Sub(n, v.s) })
			for name, vec := range map[string]ecdsaVector{"signature": v, "malleable twin": twin} {
				if !vec.hostVerifies() {
					t.Fatalf("%d %s: host rejects", i, name)
				}
				if err := solveECDSA(t, cs, vec.witness()); err != nil {
					t.Fatalf("%d %s: compiled circuit rejects: %v", i, name, err)
				}
				if err := test.IsSolved(&ecdsaCircuit{NoLookups: noLookups}, vec.witness(), ecc.BN254.ScalarField()); err != nil {
					t.Fatalf("%d %s: test engine rejects: %v", i, name, err)
				}
			}
		}
	})
}

// Invariant 2: Invalid signatures and malformed inputs are rejected.
func TestECDSARejectsInvalidSignatures(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &ecdsaCircuit{NoLookups: noLookups})
		n := GroupOrder()
		p := elliptic.P256().Params().P
		key := signingKey(t)
		v := signedVector(t, key, "spend")
		other := signingKey(t)
		rows := map[string]ecdsaVector{
			"wrong message":      v.with(func(w *ecdsaVector) { w.h = new(big.Int).Add(v.h, big.NewInt(1)) }),
			"wrong key":          v.with(func(w *ecdsaVector) { w.x, w.y = other.X, other.Y }),
			"negated key":        v.with(func(w *ecdsaVector) { w.y = new(big.Int).Sub(p, v.y) }),
			"r zero":             v.with(func(w *ecdsaVector) { w.r = big.NewInt(0) }),
			"s zero":             v.with(func(w *ecdsaVector) { w.s = big.NewInt(0) }),
			"r group order":      v.with(func(w *ecdsaVector) { w.r = n }),
			"s group order":      v.with(func(w *ecdsaVector) { w.s = n }),
			"r plus order":       v.with(func(w *ecdsaVector) { w.r = new(big.Int).Add(v.r, n) }),
			"s plus order":       v.with(func(w *ecdsaVector) { w.s = new(big.Int).Add(v.s, n) }),
			"r and s swapped":    v.with(func(w *ecdsaVector) { w.r, w.s = v.s, v.r }),
			"r negated":          v.with(func(w *ecdsaVector) { w.r = new(big.Int).Sub(n, v.r) }),
			"key x plus p":       v.with(func(w *ecdsaVector) { w.x = new(big.Int).Add(v.x, p) }),
			"key off curve":      v.with(func(w *ecdsaVector) { w.y = new(big.Int).Add(v.y, big.NewInt(1)) }),
			"key at infinity":    v.with(func(w *ecdsaVector) { w.x, w.y = big.NewInt(0), big.NewInt(0) }),
			"message plus 2^256": v.with(func(w *ecdsaVector) { w.h = new(big.Int).Add(v.h, pow2(256)) }),
		}
		for name, row := range rows {
			t.Run(name, func(t *testing.T) {
				if row.hostVerifies() {
					t.Fatal("host accepts the vector")
				}
				if solveECDSA(t, cs, row.witness()) == nil {
					t.Fatal("compiled circuit accepts")
				}
			})
		}
		t.Run("limbs above 64 bits", func(t *testing.T) {
			w := v.witness()
			w.R[0] = new(big.Int).Add(w.R[0].(*big.Int), pow2(64))
			w.R[1] = new(big.Int).Sub(w.R[1].(*big.Int), big.NewInt(1))
			if w.R[1].(*big.Int).Sign() < 0 {
				t.Skip("second limb is zero")
			}
			if solveECDSA(t, cs, w) == nil {
				t.Fatal("compiled circuit accepts a non-canonical limb split")
			}
		})
	})
}

// Invariant 3: ECDSA accepts exceptional signature scalars and a zero message digest.
func TestECDSAAcceptsExceptionalScalars(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &ecdsaCircuit{NoLookups: noLookups})
		n := GroupOrder()
		d := new(big.Int).SetBytes([]byte("a private key for exceptional u2"))
		u1 := new(big.Int).SetBytes([]byte("the generator scalar of the test"))
		third := new(big.Int).ModInverse(big.NewInt(3), n)
		neg := func(v *big.Int) *big.Int { return new(big.Int).Sub(n, v) }
		for name, scalars := range map[string][2]*big.Int{
			"u2 one":             {u1, big.NewInt(1)},
			"u2 minus one":       {u1, neg(big.NewInt(1))},
			"u2 three":           {u1, big.NewInt(3)},
			"u2 minus three":     {u1, neg(big.NewInt(3))},
			"u2 one third":       {u1, third},
			"u2 minus one third": {u1, neg(third)},
			"u1 zero":            {big.NewInt(0), big.NewInt(5)},
		} {
			t.Run(name, func(t *testing.T) {
				v := vectorWithScalars(t, d, scalars[0], scalars[1])
				if !v.hostVerifies() {
					t.Fatal("host rejects the constructed signature")
				}
				if err := solveECDSA(t, cs, v.witness()); err != nil {
					t.Fatalf("exceptional scalar rejected: %v", err)
				}
			})
		}
		control := vectorWithScalars(t, d, u1, big.NewInt(5))
		if err := solveECDSA(t, cs, control.witness()); err != nil {
			t.Fatalf("control signature rejected: %v", err)
		}
	})
}

// Invariant 4: Forged reports and mutated hints cannot satisfy signature verification.
func TestECDSARejectsReportForgery(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &ecdsaCircuit{NoLookups: noLookups})
		real := reportVector(t, reportRealM, reportRealR, reportRealS)
		fake := reportVector(t, reportFakeM, reportFakeR, reportFakeS)
		if !real.hostVerifies() || fake.hostVerifies() {
			t.Fatal("report vectors do not match the report")
		}
		if err := solveECDSA(t, cs, real.witness()); err != nil {
			t.Fatalf("genuine report signature rejected: %v", err)
		}
		if solveECDSA(t, cs, fake.witness()) == nil {
			t.Fatal("honest prover proves the forged signature")
		}
		n := GroupOrder()
		u2 := new(big.Int).ModInverse(fake.s, n)
		u2.Mul(u2, fake.r).Mod(u2, n)
		if u2.Cmp(new(big.Int).Sub(n, big.NewInt(1))) != 0 {
			t.Fatal("the report forgery uses r/s = -1")
		}
		forgedX, forgedY := hexInt(t, reportFakeX), hexInt(t, reportFakeY)
		attacks := map[string]*big.Int{"report result": forgedX, "result of another x": new(big.Int).Add(forgedX, big.NewInt(1))}
		for name, x := range attacks {
			t.Run(name, func(t *testing.T) {
				called := 0
				count := func(h solver.Hint) solver.Hint {
					return func(q *big.Int, inputs, outputs []*big.Int) error {
						called++
						return h(q, inputs, outputs)
					}
				}
				err := solveECDSA(t, cs, fake.witness(),
					solver.OverrideHint(solver.GetHintID(p256DecomposeScalarHint), count(equalHalvesDecompositionHint)),
					solver.OverrideHint(solver.GetHintID(p256ScalarMulHint), count(fixedResultHint(x, forgedY))),
				)
				if called != 2 {
					t.Fatalf("forged hints ran %d times, want 2", called)
				}
				if err == nil {
					t.Fatal("forged signature accepted")
				}
			})
		}
	})
}

// Invariant 4: Forged reports and mutated hints cannot satisfy signature verification.
func TestECDSARejectsForgedHints(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &ecdsaCircuit{NoLookups: noLookups})
		v := signedVector(t, signingKey(t), "spend")
		n := GroupOrder()
		if err := solveECDSA(t, cs, v.witness()); err != nil {
			t.Fatalf("honest witness: %v", err)
		}
		u2 := new(big.Int).ModInverse(v.s, n)
		u2.Mul(u2, v.r).Mod(u2, n)
		forgeries := []struct {
			name string
			hint solver.Hint
			with solver.Hint
			also []solver.Option
		}{
			{"inverse plus one", p256ScalarInverseHint, func(q *big.Int, inputs, outputs []*big.Int) error {
				return emfield.Unwrap(q, inputs, outputs, func(m *big.Int, _, in, out []*big.Int) error {
					out[0].ModInverse(in[0], m).Add(out[0], big.NewInt(1))
					return nil
				})
			}, nil},
			{"inverse zero", p256ScalarInverseHint, func(q *big.Int, inputs, outputs []*big.Int) error {
				return emfield.Unwrap(q, inputs, outputs, func(_ *big.Int, _, _, _ []*big.Int) error { return nil })
			}, nil},
			{"inverse of the negated s", p256ScalarInverseHint, func(q *big.Int, inputs, outputs []*big.Int) error {
				return emfield.Unwrap(q, inputs, outputs, func(m *big.Int, _, in, out []*big.Int) error {
					out[0].ModInverse(new(big.Int).Sub(m, in[0]), m)
					return nil
				})
			}, nil},
			{"order wrap flipped", p256OrderWrapHint, func(q *big.Int, inputs, outputs []*big.Int) error {
				if err := p256OrderWrapHint(q, inputs, outputs); err != nil {
					return err
				}
				outputs[0].Xor(outputs[0], big.NewInt(1))
				return nil
			}, nil},
			{"limb split", p256SplitLowBitsHint, func(_ *big.Int, inputs, outputs []*big.Int) error {
				n := uint(inputs[1].Uint64())
				outputs[0].Rsh(inputs[0], n).Sub(outputs[0], big.NewInt(1))
				outputs[1].And(inputs[0], new(big.Int).Sub(pow2(int(n)), big.NewInt(1))).Add(outputs[1], pow2(int(n)))
				return nil
			}, nil},
			{"ladder result negated", p256ScalarMulHint, forgedScalarMulHint(func(s *big.Int) *big.Int { return new(big.Int).Sub(n, s) }), nil},
			{"ladder result plus Q", p256ScalarMulHint, forgedScalarMulHint(func(s *big.Int) *big.Int { return new(big.Int).Add(s, big.NewInt(1)) }), nil},
			{"consistent ladder for another scalar", p256ScalarMulHint, forgedScalarMulHint(func(s *big.Int) *big.Int { return new(big.Int).Add(s, big.NewInt(1)) }),
				[]solver.Option{solver.OverrideHint(solver.GetHintID(p256DecomposeScalarHint), forgedDecompositionHint(new(big.Int).Add(u2, big.NewInt(1))))}},
			{"decomposition of another scalar", p256DecomposeScalarHint, forgedDecompositionHint(new(big.Int).Add(u2, big.NewInt(1))), nil},
			{"comb recoding of another scalar", p256CombRecodeHint, func(q *big.Int, inputs, outputs []*big.Int) error {
				shifted := []*big.Int{new(big.Int).Add(inputs[0], big.NewInt(1))}
				return p256CombRecodeHint(q, append(shifted, inputs[1:]...), outputs)
			}, nil},
			{"x-coordinates claimed equal", p256XEqualHint, func(_ *big.Int, _, outputs []*big.Int) error {
				outputs[0].SetUint64(1)
				outputs[1].SetUint64(0)
				return nil
			}, nil},
			{"unified slope", p256UnifiedSlopeHint, shiftedSlopeHint(func(p *big.Int, in []*big.Int) *big.Int {
				return modRatio(p, new(big.Int).Sub(in[3], in[1]), new(big.Int).Sub(in[2], in[0]))
			}), nil},
			{"balanced slope limb", emfield.BalanceHint, func(q *big.Int, inputs, outputs []*big.Int) error {
				if err := emfield.BalanceHint(q, inputs, outputs); err != nil {
					return err
				}
				outputs[0].Xor(outputs[0], big.NewInt(1))
				return nil
			}, nil},
		}
		for _, f := range forgeries {
			t.Run(f.name, func(t *testing.T) {
				called := false
				with := func(q *big.Int, inputs, outputs []*big.Int) error {
					called = true
					return f.with(q, inputs, outputs)
				}
				err := solveECDSA(t, cs, v.witness(), append(f.also, solver.OverrideHint(solver.GetHintID(f.hint), with))...)
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

// Invariant 5: The verification x-coordinate is compared modulo the group order, including wraparound.
func TestECDSAComparesXModuloOrder(t *testing.T) {
	cs := compile(t, &orderWrapCircuit{})
	n := GroupOrder()
	p := elliptic.P256().Params().P
	small := big.NewInt(5)
	above := new(big.Int).Add(n, small)
	top := new(big.Int).Sub(p, big.NewInt(1))
	for _, row := range []struct {
		name   string
		x, r   *big.Int
		accept bool
	}{
		{"x below the order", small, small, true},
		{"x above the order", above, small, true},
		{"largest x", top, new(big.Int).Sub(top, n), true},
		{"x above the order compared unreduced", above, above, false},
		{"off by one", above, big.NewInt(4), false},
		{"r of another x", small, big.NewInt(6), false},
		{"x plus p", new(big.Int).Add(small, p), new(big.Int).Sub(new(big.Int).Add(small, p), n), false},
	} {
		w := &orderWrapCircuit{}
		copy(w.X[:], fieldLimbValues(row.x))
		copy(w.R[:], fieldLimbValues(row.r))
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(witness); (err == nil) != row.accept {
			t.Fatalf("%s: accept=%v err=%v", row.name, row.accept, err)
		}
	}
}

// Invariant 5: Valid signatures accept point additions whose x-coordinates collide modulo BN254.
func TestECDSAAcceptsNativeModulusXDifference(t *testing.T) {
	curve := elliptic.P256()
	p, n := curve.Params().P, GroupOrder()
	var v ecdsaVector
	for u1 := int64(1); u1 < 100; u1++ {
		ax, ay := curve.ScalarBaseMult(big.NewInt(u1).Bytes())
		bx := new(big.Int).Add(ax, ecc.BN254.ScalarField())
		if bx.Cmp(p) >= 0 {
			continue
		}
		rhs := new(big.Int).Exp(bx, big.NewInt(3), p)
		rhs.Sub(rhs, new(big.Int).Mul(bx, big.NewInt(3))).Add(rhs, curve.Params().B).Mod(rhs, p)
		by := new(big.Int).ModSqrt(rhs, p)
		if by == nil {
			continue
		}
		qx, qy := curve.ScalarMult(bx, by, new(big.Int).ModInverse(big.NewInt(2), n).Bytes())
		rx, _ := curve.Add(ax, ay, bx, by)
		r := new(big.Int).Mod(rx, n)
		s := new(big.Int).Mul(r, new(big.Int).ModInverse(big.NewInt(2), n))
		s.Mod(s, n)
		h := new(big.Int).Mul(big.NewInt(u1), s)
		h.Mod(h, n)
		v = ecdsaVector{x: qx, y: qy, h: h, r: r, s: s}
		if !v.hostVerifies() {
			t.Fatal("invalid reference signature")
		}
		t.Logf("u1=%d u2=2", u1)
		break
	}
	if v.x == nil {
		t.Fatal("no vector found")
	}
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &ecdsaCircuit{NoLookups: noLookups})
		hit := false
		record := solver.OverrideHint(solver.GetHintID(p256XEqualHint), func(q *big.Int, inputs, outputs []*big.Int) error {
			width, limbs := inputs[0], inputs[1:]
			half := len(limbs) / 2
			x1 := limbHintValue(append([]*big.Int{width}, limbs[:half]...))
			x2 := limbHintValue(append([]*big.Int{width}, limbs[half:]...))
			d := new(big.Int).Sub(x1, x2)
			hit = hit || (d.Sign() != 0 && new(big.Int).Mod(d, q).Sign() == 0)
			return p256XEqualHint(q, inputs, outputs)
		})
		if err := solveECDSA(t, cs, v.witness(), record); err != nil {
			t.Fatal(err)
		}
		if !hit {
			t.Fatal("did not reach the colliding addition")
		}
	})
}

// Diagnostic 6: signature constraint counts are recorded for both range-check modes.
func TestECDSAConstraintCount(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		cs := compile(t, &ecdsaCircuit{NoLookups: noLookups})
		wires := cs.GetNbInternalVariables() + cs.GetNbSecretVariables() + cs.GetNbPublicVariables()
		t.Logf("ecdsa constraints %7d wires %7d commitments %d", cs.GetNbConstraints(), wires, len(cs.GetCommitments().CommitmentIndexes()))
	})
}

// Invariant 7: ECDSA rejects source limbs wider than the native field.
func TestECDSARejectsWideNativeLimbs(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &wideRelimbCircuit{NoLookups: noLookups})
		if err == nil || !strings.Contains(err.Error(), "limbs do not tile the field layout") {
			t.Fatalf("expected layout rejection, got %v", err)
		}
	})
}

// Test circuits and shared helpers.

type ecdsaCircuit struct {
	NoLookups  bool `gnark:"-"`
	PublicKeyX [4]frontend.Variable
	PublicKeyY [4]frontend.Variable
	R          [4]frontend.Variable
	S          [4]frontend.Variable
	Message    [4]frontend.Variable
	Identity   [32]frontend.Variable `gnark:",public"`
}

func (c *ecdsaCircuit) Define(api frontend.API) error {
	got := VerifyECDSAFor(api, ECDSAInputs{
		LimbBits:   64,
		PublicKeyX: c.PublicKeyX[:],
		PublicKeyY: c.PublicKeyY[:],
		R:          c.R[:],
		S:          c.S[:],
		Message:    c.Message[:],
	}, !c.NoLookups)
	assertBytesEqual(api, got[:], c.Identity[:])
	return nil
}

type ecdsaVector struct {
	x, y, h, r, s *big.Int
}

func limbs64(v *big.Int) [4]frontend.Variable {
	var out [4]frontend.Variable
	mask := new(big.Int).Sub(pow2(64), big.NewInt(1))
	for i := range out {
		limb := new(big.Int).Rsh(v, uint(64*i))
		if i < len(out)-1 {
			limb.And(limb, mask)
		}
		out[i] = limb
	}
	return out
}

func (v ecdsaVector) witness() *ecdsaCircuit {
	w := &ecdsaCircuit{
		PublicKeyX: limbs64(v.x),
		PublicKeyY: limbs64(v.y),
		R:          limbs64(v.r),
		S:          limbs64(v.s),
		Message:    limbs64(v.h),
	}
	setBytes(w.Identity[:], new(big.Int).Mod(v.x, elliptic.P256().Params().P).FillBytes(make([]byte, 32)))
	return w
}

func (v ecdsaVector) with(edit func(*ecdsaVector)) ecdsaVector {
	out := v
	edit(&out)
	return out
}

func (v ecdsaVector) hostVerifies() (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if v.h.BitLen() > 256 {
		return false
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: v.x, Y: v.y}
	return ecdsa.Verify(pub, v.h.FillBytes(make([]byte, 32)), v.r, v.s)
}

func hexInt(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("bad hex %q", s)
	}
	return v
}

func signedVector(t *testing.T, key *ecdsa.PrivateKey, message string) ecdsaVector {
	t.Helper()
	digest := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return ecdsaVector{x: key.X, y: key.Y, h: new(big.Int).SetBytes(digest[:]), r: r, s: s}
}

func signingKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return key
}

func vectorWithScalars(t *testing.T, d, u1, u2 *big.Int) ecdsaVector {
	t.Helper()
	n := GroupOrder()
	_, g := secp256r1.Generators()
	var pub, nonce secp256r1.G1Affine
	pub.ScalarMultiplication(&g, d)
	k := new(big.Int).Mul(u2, d)
	k.Add(k, u1).Mod(k, n)
	nonce.ScalarMultiplication(&g, k)
	var x, y, qx big.Int
	pub.X.BigInt(&x)
	pub.Y.BigInt(&y)
	nonce.X.BigInt(&qx)
	r := new(big.Int).Mod(&qx, n)
	s := new(big.Int).ModInverse(u2, n)
	s.Mul(s, r).Mod(s, n)
	h := new(big.Int).Mul(u1, s)
	h.Mod(h, n)
	return ecdsaVector{x: &x, y: &y, h: h, r: r, s: s}
}

func solveECDSA(t *testing.T, cs constraint.ConstraintSystem, w *ecdsaCircuit, opts ...solver.Option) error {
	t.Helper()
	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	err = cs.IsSolved(witness, opts...)
	if err != nil && !strings.Contains(err.Error(), "is not satisfied") {
		t.Fatalf("expected a constraint failure, got: %v", err)
	}
	return err
}

const (
	reportPkX   = "696d724d9ca18306d21e5849dd0b45cdbdad0a5878e8ee1f9679d49d1b524d54"
	reportPkY   = "bfc64470f942da1519a5fb5dc6ad02f74ef14871c50069c912356f661336fac7"
	reportRealM = "4c1e38233ece8fd1c0caccc5e14e9f4f33419965be3f3678e81934f4d4f8b906"
	reportRealR = "7d623cc118047fc7ed7de3b453fd1e3d94e31e53987af67a8cb739cd60e567ec"
	reportRealS = "8bebf0cc45b71857599461b8d4d1780319cafed26f42330fef5171f686dd1ef2"
	reportFakeM = "391b4c3c86e2211c0f73c764280da00788a6b042ef9fe4ac2a1457825254620c"
	reportFakeR = "2dc0f7daed74d0cdf3a3802f595c5baf57d3d39f8079914d01127cdea97c7118"
	reportFakeS = "d23f0824128b2f330c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b439"
	reportFakeX = "9f7d513fd5597ad572ded15526dc54ee5e7f82907e239275ee6aa681c9ec1534"
	reportFakeY = "4039bb8e06bd25ebe65a04a23952fd08b10eb78f3aff9636edca9099ecc90538"
)

func reportVector(t *testing.T, m, r, s string) ecdsaVector {
	return ecdsaVector{x: hexInt(t, reportPkX), y: hexInt(t, reportPkY), h: hexInt(t, m), r: hexInt(t, r), s: hexInt(t, s)}
}

func fixedResultHint(x, y *big.Int) solver.Hint {
	return func(q *big.Int, inputs, outputs []*big.Int) error {
		return emfield.Unwrap(q, inputs, outputs, func(_ *big.Int, _, _, out []*big.Int) error {
			out[0].Set(x)
			out[1].Set(y)
			return nil
		})
	}
}

type orderWrapCircuit struct {
	X, R [8]frontend.Variable
}

func (c *orderWrapCircuit) Define(api frontend.API) error {
	cv := newCurve(api)
	r := cv.fr.FromLimbs(c.R[:])
	cv.fr.AssertCanonical(r)
	cv.assertXModOrder(cv.fp.FromLimbs(c.X[:]), r)
	return nil
}

type wideRelimbCircuit struct {
	NoLookups bool `gnark:"-"`
	Input     frontend.Variable
	Output    [8]frontend.Variable `gnark:",public"`
}

func (c *wideRelimbCircuit) Define(api frontend.API) error {
	cv := newCurveFor(api, !c.NoLookups)
	out := cv.relimb([]frontend.Variable{c.Input}, 256)
	for i := range out {
		api.AssertIsEqual(out[i], c.Output[i])
	}
	return nil
}
