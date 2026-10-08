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
//  5. Field-coordinate bytes are canonical (emcurve TestLimbsBelowModulus).
//  6. Forged scalar-multiplication reports (emcurve soundness tests) and mutated hints are rejected.
//  7. Key agreement uses one Groth16 commitment with no public variables committed.
//  8. The variable-base ladder refuses the ephemeral scalars +-1, +-3 and +-1/3.
package p256

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
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
		for _, scalar := range []*big.Int{big.NewInt(2), big.NewInt(0xc0ffee), new(big.Int).Sub(params.N, big.NewInt(2))} {
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
		if row.reduced != nil && ladderExceptional(row.reduced) {
			row.reduced = nil
		}
		t.Run(row.name, func(t *testing.T) {
			row.check(t, cs, row.agreementWitness(t, peer))
		})
	}
}

// Invariant 8: The variable-base ladder refuses the ephemeral scalars +-1, +-3 and +-1/3 for every recipient.
func TestComputeKeyAgreementRefusesLadderExceptionalScalars(t *testing.T) {
	cs := compile(t, &keyAgreementCircuit{})
	peer := agreementPeer(t)
	for _, s := range ladderExceptionalScalars() {
		if err := solveAgreement(t, cs, keyAgreementWitness(t, s, peer)); err == nil {
			t.Fatalf("scalar %x accepted", s)
		}
	}
	if err := solveAgreement(t, cs, keyAgreementWitness(t, big.NewInt(2), peer)); err != nil {
		t.Fatalf("scalar 2 rejected: %v", err)
	}
}

// Invariant 6: Forged scalar-multiplication reports and mutated hints are rejected.
func TestComputeKeyAgreementRejectsHintAttacks(t *testing.T) {
	cs := compile(t, &keyAgreementCircuit{})
	peer := agreementPeer(t)
	for _, row := range attackScalars() {
		if ladderExceptional(row.scalar) {
			continue
		}
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

// ladderExceptionalScalars mirrors hosttest.LadderExceptionalScalars, which this
// package cannot import without a cycle.
func ladderExceptionalScalars() []*big.Int {
	n := elliptic.P256().Params().N
	third := new(big.Int).ModInverse(big.NewInt(3), n)
	var out []*big.Int
	for _, s := range []*big.Int{big.NewInt(1), big.NewInt(3), third} {
		out = append(out, s, new(big.Int).Sub(n, s))
	}
	return out
}

func ladderExceptional(s *big.Int) bool {
	reduced := new(big.Int).Mod(s, elliptic.P256().Params().N)
	for _, e := range ladderExceptionalScalars() {
		if reduced.Cmp(e) == 0 {
			return true
		}
	}
	return false
}

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
