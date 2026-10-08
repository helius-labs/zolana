// Tested invariants (shared with keyagreement_external_test.go):
//
//  1. Honest key agreement matches host ECDH, including edge cases and valid zero-x
//     recipients.
//  2. Recipient encodings must have the correct prefix, canonical coordinates, and a
//     finite on-curve point.
//  3. Recipient and ephemeral-scalar inputs are constrained to bytes, including under
//     forged range-check hints.
//  4. Scalars reduce modulo the group order; zero residues are rejected, including at
//     order boundaries.
//  5. Field-coordinate bytes are canonical even when the input limbs represent a value
//     plus the field modulus.
//  6. Forged scalar-multiplication reports and mutated hints are rejected.
//  7. Key agreement uses one Groth16 commitment with no public variables committed.
package p256

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"

	"zolana/prover/prover-test/hintattack"
)

// Invariant 1: Honest key agreement matches host ECDH, including edge cases and valid zero-x recipients.
func TestComputeKeyAgreementMatchesHostECDH(t *testing.T) {
	assert := test.NewAssert(t)
	peer := agreementPeer(t)
	n := elliptic.P256().Params().N
	cs := compile(t, &keyAgreementCircuit{})
	for _, s := range []*big.Int{
		new(big.Int).SetBytes([]byte("ephemeral scalar for the merge!!")),
		big.NewInt(2),
		new(big.Int).Sub(n, big.NewInt(2)),
		new(big.Int).Add(big.NewInt(0x1234_5678), n),
	} {
		w := keyAgreementWitness(t, s, peer)
		assert.NoError(test.IsSolved(&keyAgreementCircuit{}, w, ecc.BN254.ScalarField()))
		if err := solveAgreement(t, cs, w); err != nil {
			t.Fatalf("scalar %x: %v", s, err)
		}
	}
}

// Invariant 1: Honest key agreement matches host ECDH, including edge cases and valid zero-x recipients.
func TestComputeKeyAgreementAcceptsZeroXRecipient(t *testing.T) {
	params := elliptic.P256().Params()
	y := new(big.Int).ModSqrt(params.B, params.P)
	if y == nil {
		t.Fatal("P-256 has no point at x=0")
	}
	cs := compile(t, &keyAgreementCircuit{})
	for _, y := range []*big.Int{y, new(big.Int).Sub(params.P, y)} {
		peer, err := ecdh.P256().NewPublicKey(uncompressedBytes(big.NewInt(0), y))
		if err != nil {
			t.Fatal(err)
		}
		for _, scalar := range []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(0xc0ffee), new(big.Int).Sub(params.N, big.NewInt(1))} {
			if err := solveAgreement(t, cs, keyAgreementWitness(t, scalar, peer)); err != nil {
				t.Fatalf("scalar %x, y parity %d: %v", scalar, y.Bit(0), err)
			}
		}
	}
}

// Invariant 2: Recipient encodings must have the correct prefix, canonical coordinates, and a finite on-curve point.
func TestComputeKeyAgreementRejectsMalformedInputs(t *testing.T) {
	cs := compile(t, &keyAgreementInputsCircuit{})
	n := elliptic.P256().Params().N
	p := elliptic.P256().Params().P
	scalar := new(big.Int).SetBytes([]byte("ephemeral scalar for the merge!!"))
	peer := agreementPeer(t).Bytes()
	smallX, smallY := smallXPoint(t)

	if err := solveAgreement(t, cs, inputsWitness(scalar, peer)); err != nil {
		t.Fatalf("honest inputs: %v", err)
	}
	if err := solveAgreement(t, cs, inputsWitness(scalar, uncompressedBytes(smallX, smallY))); err != nil {
		t.Fatalf("canonical small-x point: %v", err)
	}

	badPrefix := append([]byte{}, peer...)
	badPrefix[0] = 0x05
	offCurve := append([]byte{}, peer...)
	offCurve[64] ^= 1
	for _, row := range []struct {
		name      string
		scalar    *big.Int
		publicKey []byte
	}{
		{"bad prefix", scalar, badPrefix},
		{"non-canonical x", scalar, uncompressedBytes(new(big.Int).Add(smallX, p), smallY)},
		{"off-curve point", scalar, offCurve},
		{"zero scalar", big.NewInt(0), peer},
		{"scalar n", n, peer},
	} {
		t.Run(row.name, func(t *testing.T) {
			if solveAgreement(t, cs, inputsWitness(row.scalar, row.publicKey)) == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// Invariant 4: Scalars reduce modulo the group order; zero residues are rejected, including at order boundaries.
func TestComputeKeyAgreementRefusesInfinityAndReducesScalars(t *testing.T) {
	cs := compile(t, &keyAgreementCircuit{})
	peer := peerKey(t).PublicKey()
	for _, row := range scalarRows(t) {
		t.Run(row.name, func(t *testing.T) {
			row.check(t, cs, row.agreementWitness(t, peer))
		})
	}
}

// Invariant 5: Field-coordinate bytes are canonical even when the input limbs represent a value plus the field modulus.
func TestFpBytesAreCanonical(t *testing.T) {
	assert := test.NewAssert(t)
	p := emulated.P256Fp{}.Modulus()
	x := big.NewInt(0x1234_5678)
	shifted := new(big.Int).Add(x, p)
	if shifted.BitLen() > 256 {
		t.Fatalf("x + p must fit 256 bits for the test to mean anything")
	}
	assert.ProverSucceeded(&fpBytesCircuit{}, fpBytesWitness(x, x), test.WithCurves(ecc.BN254))
	assert.ProverSucceeded(&fpBytesCircuit{}, fpBytesWitness(shifted, x), test.WithCurves(ecc.BN254))
	assert.ProverFailed(&fpBytesCircuit{}, fpBytesWitness(shifted, shifted), test.WithCurves(ecc.BN254))
}

// Invariant 6: Forged scalar-multiplication reports and mutated hints are rejected.
func TestComputeKeyAgreementRejectsReportForgery(t *testing.T) {
	sameYPeer, sameYX := sameYCurvePoint(t)
	minusOne := new(big.Int).Sub(elliptic.P256().Params().N, big.NewInt(1))
	scalarMul := compile(t, &scalarMulCircuit{})
	agreement := compile(t, &keyAgreementCircuit{})
	for _, row := range []struct {
		name     string
		peer     *ecdh.PublicKey
		scalar   *big.Int
		x        *big.Int
		mirrored bool
	}{
		{"off-curve result", agreementPeer(t), minusOne, new(big.Int).SetBytes([]byte("an x nobody can recompute later!")), false},
		{"on-curve result sharing the mirrored y", sameYPeer, minusOne, sameYX, false},
		{"zero x", agreementPeer(t), minusOne, big.NewInt(0), false},
		{"on-curve result sharing the peer y at scalar one", sameYPeer, big.NewInt(1), sameYX, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := forgedWitness(t, row.peer, row.scalar, row.x)
			hints := forgedHints(t, row.x, row.mirrored)
			if err := solveAgreement(t, scalarMul, w.scalarMulWitness(), hints...); err == nil {
				t.Fatal("sw_emulated ScalarMul accepted the forged result")
			}
			if err := solveAgreement(t, agreement, w); err == nil {
				t.Fatal("honest prover produced the forged shared secret")
			}
			err := solveAgreement(t, agreement, w, hints...)
			if err == nil {
				t.Fatal("forged shared secret accepted")
			}
			t.Logf("rejected: %v", err)
		})
	}
}

// Invariant 6: Forged scalar-multiplication reports and mutated hints are rejected.
func TestComputeKeyAgreementRejectsHintAttacks(t *testing.T) {
	cs := compile(t, &keyAgreementCircuit{})
	peer := agreementPeer(t)
	for _, row := range attackScalars() {
		w := keyAgreementWitness(t, row.scalar, peer)
		t.Run(row.name, func(t *testing.T) {
			hintattack.RunHintAttacks(t, cs, func(opts ...solver.Option) error {
				return solveAgreement(t, cs, w, opts...)
			})
		})
	}
}

// Invariant 7: Key agreement uses one Groth16 commitment with no public variables committed.
func TestComputeKeyAgreementCommitmentCount(t *testing.T) {
	cs := compile(t, &keyAgreementCircuit{})
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok || len(commitments) != 1 {
		t.Fatalf("want one Groth16 commitment, got %v", cs.GetCommitments())
	}
	if n := len(commitments[0].PublicAndCommitmentCommitted); n != 0 {
		t.Fatalf("the commitment covers %d public variables", n)
	}
	variables := cs.GetNbPublicVariables() + cs.GetNbSecretVariables() + cs.GetNbInternalVariables()
	t.Logf("ComputeKeyAgreement constraints %d variables %d", cs.GetNbConstraints(), variables)
}

// Test circuits and shared helpers.

type attackScalar struct {
	name   string
	scalar *big.Int
}

func attackScalars() []attackScalar {
	return []attackScalar{
		{"scalar c0ffee", big.NewInt(0xC0FFEE)},
		{"scalar one", big.NewInt(1)},
		{"scalar minus one", new(big.Int).Sub(elliptic.P256().Params().N, big.NewInt(1))},
	}
}

type fpBytesCircuit struct {
	Limbs [4]frontend.Variable
	Bytes [32]frontend.Variable `gnark:",public"`
}

func (c *fpBytesCircuit) Define(api frontend.API) error {
	elem := emulated.Element[emulated.P256Fp]{Limbs: c.Limbs[:]}
	got, _ := canonicalFpBytes(api, newAgreementField(api), &elem)
	assertBytesEqual(api, got[:], c.Bytes[:])
	return nil
}

func fpBytesWitness(value *big.Int, bytes *big.Int) *fpBytesCircuit {
	var w fpBytesCircuit
	mask := new(big.Int).SetUint64(^uint64(0))
	for i := range w.Limbs {
		limb := new(big.Int).Rsh(value, uint(64*i))
		w.Limbs[i] = limb.And(limb, mask)
	}
	setBytes(w.Bytes[:], bytes.FillBytes(make([]byte, 32)))
	return &w
}

func (r scalarRow) agreementWitness(t *testing.T, peer *ecdh.PublicKey) *keyAgreementCircuit {
	t.Helper()
	if r.reduced != nil {
		return keyAgreementWitness(t, r.scalar, peer)
	}
	var w keyAgreementCircuit
	setBytes(w.Scalar[:], r.scalar.FillBytes(make([]byte, 32)))
	setBytes(w.PublicKey[:], peer.Bytes())
	for i := range w.Expected {
		w.Expected[i] = 0
	}
	return &w
}

type keyAgreementCircuit struct {
	Scalar    [32]frontend.Variable
	PublicKey [65]frontend.Variable
	Expected  [6]frontend.Variable `gnark:",public"`
}

func (c *keyAgreementCircuit) Define(api frontend.API) error {
	got := ComputeKeyAgreement(api, c.Scalar, c.PublicKey)
	for i, v := range []frontend.Variable{got.RecipientLo, got.RecipientHi, got.EphemeralLo, got.EphemeralHi, got.SharedLo, got.SharedHi} {
		api.AssertIsEqual(v, c.Expected[i])
	}
	return nil
}

type scalarMulCircuit struct {
	Scalar  [32]frontend.Variable
	Point   [64]frontend.Variable
	SharedX [2]frontend.Variable `gnark:",public"`
}

func (c *scalarMulCircuit) Define(api frontend.API) error {
	fp := newAgreementField(api)
	point := &agreementPoint{
		X: *fp.NewElement(agreementLimbs(api, c.Point[:32])),
		Y: *fp.NewElement(agreementLimbs(api, c.Point[32:])),
	}
	scalar := newScalarField(api).NewElement(agreementLimbs(api, c.Scalar[:]))
	shared := newP256Curve(api).ScalarMul(point, scalar)
	sharedX, _ := canonicalFpBytes(api, fp, &shared.X)
	lo, hi := packSharedX(api, sharedX[:])
	api.AssertIsEqual(lo, c.SharedX[0])
	api.AssertIsEqual(hi, c.SharedX[1])
	return nil
}

func (c *keyAgreementCircuit) scalarMulWitness() *scalarMulCircuit {
	w := scalarMulCircuit{Scalar: c.Scalar, SharedX: [2]frontend.Variable{c.Expected[4], c.Expected[5]}}
	copy(w.Point[:], c.PublicKey[1:])
	return &w
}

type keyAgreementInputsCircuit struct {
	Scalar    [32]frontend.Variable
	PublicKey [65]frontend.Variable
}

func (c *keyAgreementInputsCircuit) Define(api frontend.API) error {
	ComputeKeyAgreement(api, c.Scalar, c.PublicKey)
	return nil
}

func be32(v *big.Int) []byte {
	return v.FillBytes(make([]byte, 32))
}

func solveAgreement(t *testing.T, cs constraint.ConstraintSystem, assignment frontend.Circuit, opts ...solver.Option) error {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	return cs.IsSolved(witness, opts...)
}

func agreementPeer(t *testing.T) *ecdh.PublicKey {
	t.Helper()
	return peerKey(t).PublicKey()
}

func packAgreementBytes(bytes []byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(bytes[:31]), new(big.Int).SetBytes(bytes[31:])
}

func compressedKey(uncompressed []byte) []byte {
	x, y := elliptic.Unmarshal(elliptic.P256(), uncompressed)
	return elliptic.MarshalCompressed(elliptic.P256(), x, y)
}

func keyAgreementWitness(t *testing.T, scalar *big.Int, peer *ecdh.PublicKey) *keyAgreementCircuit {
	t.Helper()
	var w keyAgreementCircuit
	setBytes(w.Scalar[:], be32(scalar))
	setBytes(w.PublicKey[:], peer.Bytes())
	key, err := ecdh.P256().NewPrivateKey(be32(new(big.Int).Mod(scalar, elliptic.P256().Params().N)))
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	shared, err := key.ECDH(peer)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	for i, bytes := range [][]byte{compressedKey(peer.Bytes()), compressedKey(key.PublicKey().Bytes()), shared} {
		lo, hi := packAgreementBytes(bytes)
		w.Expected[2*i], w.Expected[2*i+1] = lo, hi
	}
	return &w
}

func inputsWitness(scalar *big.Int, publicKey []byte) *keyAgreementInputsCircuit {
	var w keyAgreementInputsCircuit
	setBytes(w.Scalar[:], be32(scalar))
	setBytes(w.PublicKey[:], publicKey)
	return &w
}

func smallXPoint(t *testing.T) (x, y *big.Int) {
	t.Helper()
	params := elliptic.P256().Params()
	for i := int64(1); i < 64; i++ {
		x := big.NewInt(i)
		rhs := new(big.Int).Mul(x, x)
		rhs.Mul(rhs, x).Sub(rhs, new(big.Int).Mul(big.NewInt(3), x)).Add(rhs, params.B).Mod(rhs, params.P)
		if y := new(big.Int).ModSqrt(rhs, params.P); y != nil {
			return x, y
		}
	}
	t.Fatal("no curve point with a small x")
	return nil, nil
}

func uncompressedBytes(x, y *big.Int) []byte {
	return append(append([]byte{0x04}, be32(x)...), be32(y)...)
}

func swEmulatedHint(t *testing.T, suffix string) solver.HintID {
	t.Helper()
	for _, h := range sw_emulated.GetHints() {
		if strings.HasSuffix(solver.GetHintName(h), "sw_emulated."+suffix) {
			return solver.GetHintID(h)
		}
	}
	t.Fatalf("gnark no longer registers sw_emulated.%s", suffix)
	return 0
}

var alternatingHalfScalar, _ = new(big.Int).SetString(strings.Repeat("55", 16), 16)

func forgedHints(t *testing.T, x *big.Int, mirrored bool) []solver.Option {
	t.Helper()
	decomposition := func(mod *big.Int, in, out []*big.Int) error {
		return emulated.UnwrapHintContext(mod, in, out, func(hc emulated.HintContext) error {
			moduli := hc.EmulatedModuli()
			_, sign := hc.NativeInputsOutputs()
			_, halves := hc.InputsOutputs(moduli[0])
			sign[0].SetUint64(0)
			if mirrored {
				sign[0].SetUint64(1)
			}
			halves[0].Set(alternatingHalfScalar)
			halves[1].Set(alternatingHalfScalar)
			return nil
		})
	}
	result := func(mod *big.Int, in, out []*big.Int) error {
		return emulated.UnwrapHintContext(mod, in, out, func(hc emulated.HintContext) error {
			moduli := hc.EmulatedModuli()
			point, res := hc.InputsOutputs(moduli[0])
			res[0].Set(x)
			res[1].Sub(moduli[0], point[1])
			if mirrored {
				res[1].Set(point[1])
			}
			return nil
		})
	}
	return []solver.Option{
		solver.OverrideHint(swEmulatedHint(t, "rationalReconstruct"), decomposition),
		solver.OverrideHint(swEmulatedHint(t, "scalarMulHint"), result),
	}
}

func sameYCurvePoint(t *testing.T) (*ecdh.PublicKey, *big.Int) {
	t.Helper()
	p := elliptic.P256().Params().P
	for i := byte(1); i < 255; i++ {
		seed := make([]byte, 32)
		seed[31] = i
		key, err := ecdh.P256().NewPrivateKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		x := new(big.Int).SetBytes(key.PublicKey().Bytes()[1:33])
		disc := new(big.Int).Mul(x, x)
		disc.Mul(disc, big.NewInt(-3)).Add(disc, big.NewInt(12)).Mod(disc, p)
		root := new(big.Int).ModSqrt(disc, p)
		if root == nil {
			continue
		}
		other := new(big.Int).Sub(root, x)
		other.Mul(other, new(big.Int).ModInverse(big.NewInt(2), p)).Mod(other, p)
		return key.PublicKey(), other
	}
	t.Fatal("no key whose y is shared by another curve point")
	return nil, nil
}

func forgedWitness(t *testing.T, peer *ecdh.PublicKey, scalar, x *big.Int) *keyAgreementCircuit {
	t.Helper()
	w := keyAgreementWitness(t, scalar, peer)
	lo, hi := packAgreementBytes(be32(x))
	w.Expected[4], w.Expected[5] = lo, hi
	return w
}
