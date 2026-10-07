package shared_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	customring "zolana/prover/circuits/spp_transaction/custom"
	. "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/hintattack"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256r1"
	"github.com/consensys/gnark/constraint"
	bn254cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

var (
	p256BoundaryShape = protocol.Shape{NInputs: 1, NOutputs: 2}
	p256MixedShape    = protocol.Shape{NInputs: 2, NOutputs: 2}
)

type compiledP256System struct {
	once sync.Once
	ccs  constraint.ConstraintSystem
	err  error
}

var compiledP256Systems sync.Map

func compiledCustomRingP256(t testing.TB, shape protocol.Shape) constraint.ConstraintSystem {
	t.Helper()
	entry, _ := compiledP256Systems.LoadOrStore(shape, &compiledP256System{})
	compiled := entry.(*compiledP256System)
	compiled.once.Do(func() {
		start := time.Now()
		compiled.ccs, compiled.err = frontend.Compile(
			ecc.BN254.ScalarField(),
			r1cs.NewBuilder,
			MustNewCustomRingP256Circuit(Shape(shape)),
			frontend.WithCompressThreshold(300),
		)
		if compiled.err == nil {
			t.Logf(
				"compiled CustomRingP256 %dx%d: %d constraints in %s",
				shape.NInputs, shape.NOutputs, compiled.ccs.GetNbConstraints(), time.Since(start).Round(time.Millisecond),
			)
		}
	})
	if compiled.err != nil {
		t.Fatalf("compile CustomRingP256 %dx%d: %v", shape.NInputs, shape.NOutputs, compiled.err)
	}
	return compiled.ccs
}

func solveCustomRingP256(ccs constraint.ConstraintSystem, assignment frontend.Circuit, opts ...solver.Option) error {
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("new witness: %w", err)
	}
	return ccs.IsSolved(w, opts...)
}

func lenientP256Options(t testing.TB) []solver.Option {
	t.Helper()
	return append(hintattack.LenientZeroChecks(), hintattack.SkipMissingLookupQueries(t))
}

func assertCustomRingP256Solves(t *testing.T, ccs constraint.ConstraintSystem, assignment frontend.Circuit) {
	t.Helper()
	start := time.Now()
	if err := solveCustomRingP256(ccs, assignment); err != nil {
		t.Fatalf("honest witness rejected: %v", err)
	}
	t.Logf("solved in %s", time.Since(start).Round(time.Millisecond))
}

func assertCustomRingP256Rejected(t *testing.T, ccs constraint.ConstraintSystem, assignment frontend.Circuit, opts ...solver.Option) {
	t.Helper()
	hintattack.RequireConstraintRejection(t, solveCustomRingP256(ccs, assignment, append(lenientP256Options(t), opts...)...))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func p256Digest(authorization p256Authorization) [32]byte {
	var digest [32]byte
	authorization.high.FillBytes(digest[:16])
	authorization.low.FillBytes(digest[16:])
	return digest
}

func p256IdentityOfX(t testing.TB, x *big.Int) *big.Int {
	t.Helper()
	if x.Sign() < 0 || x.BitLen() > 256 {
		t.Fatalf("x %x does not fit 32 bytes", x)
	}
	var xBytes [32]byte
	x.FillBytes(xBytes[:])
	identity, err := protocol.HashBytes(append([]byte{protocol.P256OwnerTag}, xBytes[:]...))
	if err != nil {
		t.Fatalf("P256 identity: %v", err)
	}
	return identity
}

func p256FpElement(t testing.TB, value *big.Int) emulated.Element[emulated.P256Fp] {
	t.Helper()
	nbLimbs, nbBits := emulated.GetEffectiveFieldParams[emulated.P256Fp](ecc.BN254.ScalarField())
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), nbBits), big.NewInt(1))
	rest := new(big.Int).Set(value)
	limbs := make([]frontend.Variable, nbLimbs)
	for i := range limbs {
		limbs[i] = new(big.Int).And(rest, mask)
		rest.Rsh(rest, nbBits)
	}
	if rest.Sign() != 0 {
		t.Fatalf("value %x does not fit %d limbs of %d bits", value, nbLimbs, nbBits)
	}
	return emulated.Element[emulated.P256Fp]{Limbs: limbs}
}

func honestP256Assignment(t testing.TB, shape protocol.Shape, owner *ecdsa.PrivateKey) (*testAssignment, p256Authorization) {
	t.Helper()
	assignment := buildCircuitAssignment(t, shape)
	rewriteInputAsP256(t, assignment, 0, owner)
	return assignment, authorizeP256(t, assignment, owner, owner)
}

func signP256Digest(t testing.TB, signer *ecdsa.PrivateKey, digest [32]byte) customring.P256Signature {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, signer, digest[:])
	if err != nil {
		t.Fatalf("sign P256 digest: %v", err)
	}
	return customring.P256Signature{
		R: emulated.ValueOf[emulated.P256Fr](r),
		S: emulated.ValueOf[emulated.P256Fr](s),
	}
}

func TestCustomRingP256RejectsInfinityPublicKey(t *testing.T) {
	ccs := compiledCustomRingP256(t, p256BoundaryShape)
	owner := spptest.FixedP256Key(t, 11)

	t.Run("honest witness solves", func(t *testing.T) {
		assignment, authorization := honestP256Assignment(t, p256BoundaryShape, owner)
		assertCustomRingP256Solves(t, ccs, asCustomRingP256(assignment, authorization))
	})

	t.Run("infinity key with the identity of x zero", func(t *testing.T) {
		assignment := buildCircuitAssignment(t, p256BoundaryShape)
		identity := p256IdentityOfX(t, big.NewInt(0))
		rewriteInputAsP256WithIdentity(t, assignment, 0, identity)
		authorization := authorizeP256(t, assignment, owner, owner)
		authorization.pub = customring.P256PublicKey{
			X: emulated.ValueOf[emulated.P256Fp](0),
			Y: emulated.ValueOf[emulated.P256Fp](0),
		}
		authorization.pkHash = identity
		refreshCustomRingP256PublicInputHash(t, assignment, p256Digest(authorization), identity)
		assertCustomRingP256Rejected(t, ccs, asCustomRingP256(assignment, authorization))
	})
}

func TestCustomRingP256RejectsZeroOrOrderSignatureScalars(t *testing.T) {
	ccs := compiledCustomRingP256(t, p256BoundaryShape)
	owner := spptest.FixedP256Key(t, 11)
	assignment, honest := honestP256Assignment(t, p256BoundaryShape, owner)
	order := elliptic.P256().Params().N

	t.Run("honest witness solves", func(t *testing.T) {
		assertCustomRingP256Solves(t, ccs, asCustomRingP256(assignment, honest))
	})
	for _, row := range []struct {
		name   string
		mutate func(sig *customring.P256Signature)
	}{
		{"r zero", func(sig *customring.P256Signature) { sig.R = emulated.ValueOf[emulated.P256Fr](0) }},
		{"s zero", func(sig *customring.P256Signature) { sig.S = emulated.ValueOf[emulated.P256Fr](0) }},
		{"r group order", func(sig *customring.P256Signature) { sig.R = emulated.ValueOf[emulated.P256Fr](order) }},
		{"s group order", func(sig *customring.P256Signature) { sig.S = emulated.ValueOf[emulated.P256Fr](order) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			authorization := honest
			row.mutate(&authorization.sig)
			assertCustomRingP256Rejected(t, ccs, asCustomRingP256(assignment, authorization))
		})
	}
}

type smallXP256Key struct {
	x, y   *big.Int
	digest [32]byte
	r, s   *big.Int
}

func findSmallXP256Key(t testing.TB) smallXP256Key {
	t.Helper()
	params := elliptic.P256().Params()
	headroom := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), params.P)
	for candidate := int64(1); candidate < 1024; candidate++ {
		x := big.NewInt(candidate)
		rhs := new(big.Int).Exp(x, big.NewInt(3), params.P)
		rhs.Sub(rhs, new(big.Int).Mul(big.NewInt(3), x))
		rhs.Add(rhs, params.B)
		rhs.Mod(rhs, params.P)
		y := new(big.Int).ModSqrt(rhs, params.P)
		if y == nil {
			continue
		}
		if x.Cmp(headroom) >= 0 {
			break
		}
		key := smallXP256Key{x: x, y: y}
		key.sign(t)
		return key
	}
	t.Skip("no P-256 point with x + p < 2^256 among x in [1, 1024)")
	return smallXP256Key{}
}

func (k *smallXP256Key) sign(t testing.TB) {
	t.Helper()
	order := elliptic.P256().Params().N
	var public secp256r1.G1Affine
	public.X.SetBigInt(k.x)
	public.Y.SetBigInt(k.y)
	if !public.IsOnCurve() {
		t.Fatalf("(%x, %x) is not on P-256", k.x, k.y)
	}
	generatorScalar := big.NewInt(0xC0FFEE)
	for keyScalar := int64(0xBEEF); keyScalar < 0xBEEF+64; keyScalar++ {
		var fromGenerator, fromKey, nonce secp256r1.G1Affine
		fromGenerator.ScalarMultiplicationBase(generatorScalar)
		fromKey.ScalarMultiplication(&public, big.NewInt(keyScalar))
		nonce.Add(&fromGenerator, &fromKey)
		r := nonce.X.BigInt(new(big.Int))
		if r.Sign() == 0 || r.Cmp(order) >= 0 {
			continue
		}
		s := new(big.Int).ModInverse(big.NewInt(keyScalar), order)
		s.Mul(s, r).Mod(s, order)
		message := new(big.Int).Mul(generatorScalar, s)
		message.Mod(message, order)
		message.FillBytes(k.digest[:])
		k.r, k.s = r, s
		verifier := ecdsa.PublicKey{Curve: elliptic.P256(), X: k.x, Y: k.y}
		if !ecdsa.Verify(&verifier, k.digest[:], r, s) {
			t.Fatal("the constructed signature does not verify on the host")
		}
		return
	}
	t.Fatal("no nonce with an x-coordinate below the group order")
}

func (k smallXP256Key) authorization(t testing.TB, assignment *testAssignment, encodedX emulated.Element[emulated.P256Fp], identity *big.Int) p256Authorization {
	t.Helper()
	authorization := p256Authorization{
		pub: customring.P256PublicKey{
			X: encodedX,
			Y: emulated.ValueOf[emulated.P256Fp](k.y),
		},
		sig: customring.P256Signature{
			R: emulated.ValueOf[emulated.P256Fr](k.r),
			S: emulated.ValueOf[emulated.P256Fr](k.s),
		},
		low:    new(big.Int).SetBytes(k.digest[16:]),
		high:   new(big.Int).SetBytes(k.digest[:16]),
		pkHash: identity,
	}
	refreshCustomRingP256PublicInputHash(t, assignment, k.digest, identity)
	return authorization
}

func TestCustomRingP256RejectsNonCanonicalPublicKeyIdentity(t *testing.T) {
	ccs := compiledCustomRingP256(t, p256BoundaryShape)
	key := findSmallXP256Key(t)
	p := elliptic.P256().Params().P
	shiftedX := new(big.Int).Add(key.x, p)
	t.Logf("public key x = %d, encoded as x + p = %x (%d bits)", key.x, shiftedX, shiftedX.BitLen())
	canonicalIdentity := p256IdentityOfX(t, key.x)
	shiftedIdentity := p256IdentityOfX(t, shiftedX)

	build := func(t *testing.T, encodedX emulated.Element[emulated.P256Fp], identity *big.Int) frontend.Circuit {
		t.Helper()
		assignment := buildCircuitAssignment(t, p256BoundaryShape)
		rewriteInputAsP256WithIdentity(t, assignment, 0, identity)
		return asCustomRingP256(assignment, key.authorization(t, assignment, encodedX, identity))
	}

	t.Run("canonical encoding solves", func(t *testing.T) {
		assertCustomRingP256Solves(t, ccs, build(t, p256FpElement(t, key.x), canonicalIdentity))
	})
	t.Run("x plus p with the canonical identity", func(t *testing.T) {
		start := time.Now()
		err := solveCustomRingP256(ccs, build(t, p256FpElement(t, shiftedX), canonicalIdentity), lenientP256Options(t)...)
		if err == nil {
			t.Logf("accepted in %s: the key keeps its canonical identity", time.Since(start).Round(time.Millisecond))
			return
		}
		t.Logf("rejected in %s: %s", time.Since(start).Round(time.Millisecond), firstLine(err.Error()))
	})
	t.Run("x plus p with the identity of the 256-bit encoding", func(t *testing.T) {
		assertCustomRingP256Rejected(t, ccs, build(t, p256FpElement(t, shiftedX), shiftedIdentity))
	})
}

func withP256DataOutput(t testing.TB, assignment *testAssignment, owner *ecdsa.PrivateKey) {
	t.Helper()
	assignment.Outputs[0].Utxo.DataHash = spptest.Fe(0xDA7A)
	rewriteOutputAsP256(t, assignment, 0, owner)
}

func TestCustomRingP256RejectsOutputOnlyP256Owner(t *testing.T) {
	ccs := compiledCustomRingP256(t, p256BoundaryShape)
	owner := spptest.FixedP256Key(t, 11)
	wrongSigner := spptest.FixedP256Key(t, 12)

	t.Run("P-256 input authorizes a data output", func(t *testing.T) {
		assignment := buildCircuitAssignment(t, p256BoundaryShape)
		rewriteInputAsP256(t, assignment, 0, owner)
		withP256DataOutput(t, assignment, owner)
		assertCustomRingP256Solves(t, ccs, asCustomRingP256(assignment, authorizeP256(t, assignment, owner, owner)))
	})
	for _, row := range []struct {
		name   string
		signer *ecdsa.PrivateKey
	}{
		{"Ed25519 input with a valid P-256 signature", owner},
		{"Ed25519 input with a P-256 signature from another key", wrongSigner},
	} {
		t.Run(row.name, func(t *testing.T) {
			assignment := buildCircuitAssignment(t, p256BoundaryShape)
			withP256DataOutput(t, assignment, owner)
			if spptest.AsBigInt(assignment.Inputs[0].OwnerPkHash).Sign() == 0 {
				t.Fatal("input 0 must stay Ed25519-owned")
			}
			assertCustomRingP256Rejected(t, ccs, asCustomRingP256(assignment, authorizeP256(t, assignment, owner, row.signer)))
		})
	}
}

func TestCustomRingP256RejectsUnsignedP256InputBesideEd25519Input(t *testing.T) {
	ccs := compiledCustomRingP256(t, p256MixedShape)
	owner := spptest.FixedP256Key(t, 11)
	wrongSigner := spptest.FixedP256Key(t, 12)
	build := func(t *testing.T) *testAssignment {
		t.Helper()
		assignment := buildCircuitAssignment(t, p256MixedShape)
		rewriteInputAsP256(t, assignment, 0, owner)
		withP256DataOutput(t, assignment, owner)
		if spptest.AsBigInt(assignment.Inputs[1].OwnerPkHash).Sign() == 0 {
			t.Fatal("input 1 must stay Ed25519-owned")
		}
		return assignment
	}

	t.Run("valid signature solves", func(t *testing.T) {
		assignment := build(t)
		assertCustomRingP256Solves(t, ccs, asCustomRingP256(assignment, authorizeP256(t, assignment, owner, owner)))
	})
	t.Run("signature from another key", func(t *testing.T) {
		assignment := build(t)
		assertCustomRingP256Rejected(t, ccs, asCustomRingP256(assignment, authorizeP256(t, assignment, owner, wrongSigner)))
	})
	t.Run("signature r zero", func(t *testing.T) {
		assignment := build(t)
		authorization := authorizeP256(t, assignment, owner, owner)
		authorization.sig.R = emulated.ValueOf[emulated.P256Fr](0)
		assertCustomRingP256Rejected(t, ccs, asCustomRingP256(assignment, authorization))
	})
}

func customRingP256Hints(t testing.TB, ccs constraint.ConstraintSystem) []string {
	t.Helper()
	system, ok := ccs.(*bn254cs.R1CS)
	if !ok {
		t.Fatalf("not a BN254 R1CS: %T", ccs)
	}
	names := make([]string, 0, len(system.MHintsDependencies))
	for _, name := range system.MHintsDependencies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func containsHint(names []string, suffix string) bool {
	for _, name := range names {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func TestCustomRingP256RejectsHintAttacks(t *testing.T) {
	start := time.Now()
	ccs := compiledCustomRingP256(t, p256BoundaryShape)
	names := customRingP256Hints(t, ccs)
	t.Logf("%d hints: %s", len(names), strings.Join(names, ", "))
	assignment, authorization := honestP256Assignment(t, p256BoundaryShape, spptest.FixedP256Key(t, 11))
	w, err := frontend.NewWitness(asCustomRingP256(assignment, authorization), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	t.Logf("compiled and built the witness in %s", time.Since(start).Round(time.Millisecond))
	hintattack.RunHintAttacks(t, ccs, func(opts ...solver.Option) error {
		return ccs.IsSolved(w, opts...)
	})
	t.Logf("total %s", time.Since(start).Round(time.Millisecond))
}

func swEmulatedHint(t testing.TB, suffix string) solver.Hint {
	t.Helper()
	for _, h := range sw_emulated.GetHints() {
		if strings.HasSuffix(solver.GetHintName(h), suffix) {
			return h
		}
	}
	t.Fatalf("sw_emulated hint %s not registered", suffix)
	return nil
}

func secp256r1Point(x, y *big.Int) secp256r1.G1Affine {
	var point secp256r1.G1Affine
	point.X.SetBigInt(x)
	point.Y.SetBigInt(y)
	return point
}

type wrongKeyScalarMul struct {
	victim secp256r1.G1Affine
	signer secp256r1.G1Affine
	mu     sync.Mutex
	calls  int
	forged int
}

func (f *wrongKeyScalarMul) solve(mod *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(mod, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 2 {
			return fmt.Errorf("scalar mul: want two moduli, got %d", len(moduli))
		}
		baseInputs, baseOutputs := hc.InputsOutputs(moduli[0])
		scalarInputs, _ := hc.InputsOutputs(moduli[1])
		if len(baseInputs) != 2 || len(baseOutputs) != 2 || len(scalarInputs) != 1 {
			return fmt.Errorf("scalar mul: unexpected layout %d/%d/%d", len(baseInputs), len(baseOutputs), len(scalarInputs))
		}
		point := secp256r1Point(baseInputs[0], baseInputs[1])
		source := &point
		f.mu.Lock()
		f.calls++
		if point.Equal(&f.victim) {
			source = &f.signer
			f.forged++
		}
		f.mu.Unlock()
		var result secp256r1.G1Affine
		result.ScalarMultiplication(source, scalarInputs[0])
		result.X.BigInt(baseOutputs[0])
		result.Y.BigInt(baseOutputs[1])
		return nil
	})
}

func TestCustomRingP256BoundaryRejectsWrongKeyScalarMulForgery(t *testing.T) {
	ccs := compiledCustomRingP256(t, p256BoundaryShape)
	names := customRingP256Hints(t, ccs)
	if !containsHint(names, hintattack.ScalarMulHint) || !containsHint(names, hintattack.RationalReconstruct) {
		t.Skipf("the P-256 rail calls no hinted scalar multiplication (JointScalarMulBase uses only comb and fixed-base paths): %v", names)
	}
	owner := spptest.FixedP256Key(t, 11)
	wrongSigner := spptest.FixedP256Key(t, 12)
	assignment, authorization := honestP256Assignment(t, p256BoundaryShape, owner)
	digest := p256Digest(authorization)
	r, s, err := ecdsa.Sign(rand.Reader, wrongSigner, digest[:])
	if err != nil {
		t.Fatalf("sign with the wrong key: %v", err)
	}
	if !ecdsa.Verify(&wrongSigner.PublicKey, digest[:], r, s) || ecdsa.Verify(&owner.PublicKey, digest[:], r, s) {
		t.Fatal("the forged signature must verify for the wrong key only")
	}
	authorization.sig = customring.P256Signature{
		R: emulated.ValueOf[emulated.P256Fr](r),
		S: emulated.ValueOf[emulated.P256Fr](s),
	}

	order := elliptic.P256().Params().N
	sInverse := new(big.Int).ModInverse(s, order)
	keyScalar := new(big.Int).Mul(r, sInverse)
	keyScalar.Mod(keyScalar, order)
	messageScalar := new(big.Int).Mul(new(big.Int).SetBytes(digest[:]), sInverse)
	messageScalar.Mod(messageScalar, order)
	signerPoint := secp256r1Point(wrongSigner.PublicKey.X, wrongSigner.PublicKey.Y)
	var fromGenerator, fromKey, combined secp256r1.G1Affine
	fromGenerator.ScalarMultiplicationBase(messageScalar)
	fromKey.ScalarMultiplication(&signerPoint, keyScalar)
	combined.Add(&fromGenerator, &fromKey)
	if combined.X.BigInt(new(big.Int)).Cmp(r) != 0 {
		t.Fatal("the forged scalar mul result does not reach x = r")
	}

	t.Run("honest scalar mul rejects the wrong key", func(t *testing.T) {
		assertCustomRingP256Rejected(t, ccs, asCustomRingP256(assignment, authorization))
	})
	t.Run("scalar mul hint returns the wrong key's multiple", func(t *testing.T) {
		forgery := &wrongKeyScalarMul{
			victim: secp256r1Point(owner.PublicKey.X, owner.PublicKey.Y),
			signer: signerPoint,
		}
		override := solver.OverrideHint(solver.GetHintID(swEmulatedHint(t, hintattack.ScalarMulHint)), forgery.solve)
		assertCustomRingP256Rejected(t, ccs, asCustomRingP256(assignment, authorization), override)
		if forgery.forged == 0 {
			t.Fatalf("the scalar mul hint was called %d times but never on the public key", forgery.calls)
		}
		t.Logf("forged %d of %d scalar mul hint calls", forgery.forged, forgery.calls)
	})
}
