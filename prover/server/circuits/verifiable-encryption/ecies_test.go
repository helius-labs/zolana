package verifiableencryption_test

import (
	"crypto/ecdh"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/prover-test/hosttest"
)

const eciesPlaintextBytes = 40

var (
	testSecretTag = []byte("TMES")
	testKdfInfo   = []byte("TMEC")
)

type envelopeCircuit struct {
	EphemeralSk [ve.ScalarBytes]frontend.Variable
	RecipientPk [ve.UncompressedPointBytes]frontend.Variable
	Plaintext   []frontend.Variable
	RecipientLo frontend.Variable   `gnark:",public"`
	RecipientHi frontend.Variable   `gnark:",public"`
	EphemeralLo frontend.Variable   `gnark:",public"`
	EphemeralHi frontend.Variable   `gnark:",public"`
	Ciphertext  []frontend.Variable `gnark:",public"`
}

func newEnvelopeCircuit(n int) *envelopeCircuit {
	return &envelopeCircuit{Plaintext: make([]frontend.Variable, n), Ciphertext: make([]frontend.Variable, n)}
}

func (c *envelopeCircuit) Define(api frontend.API) error {
	sealed := ve.Envelope{
		SecretTag:   testSecretTag,
		KdfInfo:     testKdfInfo,
		EphemeralSk: c.EphemeralSk,
		RecipientPk: c.RecipientPk,
		Plaintext:   c.Plaintext,
	}.Seal(api)
	api.AssertIsEqual(sealed.RecipientLo, c.RecipientLo)
	api.AssertIsEqual(sealed.RecipientHi, c.RecipientHi)
	api.AssertIsEqual(sealed.EphemeralLo, c.EphemeralLo)
	api.AssertIsEqual(sealed.EphemeralHi, c.EphemeralHi)
	for i, b := range sealed.Ciphertext {
		api.AssertIsEqual(b, c.Ciphertext[i])
	}
	return nil
}

func envelopePlaintext(n int) []byte {
	plaintext := make([]byte, n)
	for i := range plaintext {
		plaintext[i] = byte(31*i + 5)
	}
	return plaintext
}

type envelopeInputs struct {
	ephemeralSk [32]byte
	recipientPk [65]byte
	recipientLo *big.Int
	recipientHi *big.Int
	ephemeralLo *big.Int
	ephemeralHi *big.Int
	plaintext   []byte
	ciphertext  []byte
}

func (in envelopeInputs) witness() *envelopeCircuit {
	a := newEnvelopeCircuit(len(in.plaintext))
	a.RecipientLo, a.RecipientHi = in.recipientLo, in.recipientHi
	a.EphemeralLo, a.EphemeralHi = in.ephemeralLo, in.ephemeralHi
	for i, b := range in.ephemeralSk {
		a.EphemeralSk[i] = b
	}
	for i, b := range in.recipientPk {
		a.RecipientPk[i] = b
	}
	for i := range in.plaintext {
		a.Plaintext[i] = in.plaintext[i]
		a.Ciphertext[i] = in.ciphertext[i]
	}
	return a
}

func envelopeAssignment(n int) *envelopeCircuit {
	keys := hosttest.DefaultKeys()
	plaintext := envelopePlaintext(n)
	ciphertext, _ := keys.Seal(testSecretTag, testKdfInfo, plaintext)
	recipientLo, recipientHi := keys.RecipientPacked()
	ephemeralLo, ephemeralHi := keys.EphemeralPacked()
	return envelopeInputs{
		ephemeralSk: keys.EphemeralScalar(),
		recipientPk: keys.RecipientUncompressed(),
		recipientLo: recipientLo,
		recipientHi: recipientHi,
		ephemeralLo: ephemeralLo,
		ephemeralHi: ephemeralHi,
		plaintext:   plaintext,
		ciphertext:  ciphertext,
	}.witness()
}

func compileEnvelope(t *testing.T, n int) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, newEnvelopeCircuit(n))
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func solveCompiled(t *testing.T, cs constraint.ConstraintSystem, assignment frontend.Circuit, opts ...solver.Option) error {
	t.Helper()
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return cs.IsSolved(w, opts...)
}

func TestEnvelopeMatchesHost(t *testing.T) {
	for _, n := range []int{16, eciesPlaintextBytes} {
		if err := test.IsSolved(newEnvelopeCircuit(n), envelopeAssignment(n), ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("%d bytes: test engine: %v", n, err)
		}
		if err := solveCompiled(t, compileEnvelope(t, n), envelopeAssignment(n)); err != nil {
			t.Fatalf("%d bytes: compiled R1CS: %v", n, err)
		}
	}
}

func TestEnvelopeRejectsTamperedCiphertext(t *testing.T) {
	a := envelopeAssignment(eciesPlaintextBytes)
	a.Ciphertext[eciesPlaintextBytes-1] = a.Ciphertext[eciesPlaintextBytes-1].(byte) ^ 1
	if err := test.IsSolved(newEnvelopeCircuit(eciesPlaintextBytes), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("a tampered ciphertext was accepted")
	}
}

func TestEnvelopeRejectsForeignRecipient(t *testing.T) {
	other, err := ecdh.P256().NewPrivateKey(append(make([]byte, 31), 0x2c))
	if err != nil {
		t.Fatal(err)
	}
	a := envelopeAssignment(eciesPlaintextBytes)
	for i, b := range other.PublicKey().Bytes() {
		a.RecipientPk[i] = b
	}
	if err := test.IsSolved(newEnvelopeCircuit(eciesPlaintextBytes), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("a foreign recipient key was accepted")
	}
}

func TestEnvelopeCommitmentCount(t *testing.T) {
	cs := compileEnvelope(t, eciesPlaintextBytes)
	t.Logf("envelope over %d bytes: %d constraints, %d BSB22 commitments", eciesPlaintextBytes, cs.GetNbConstraints(), len(cs.GetCommitments().CommitmentIndexes()))
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok || len(commitments) != 1 {
		t.Fatalf("want one Groth16 commitment, got %v", cs.GetCommitments())
	}
	if n := len(commitments[0].PublicAndCommitmentCommitted); n != 0 {
		t.Fatalf("the commitment covers %d public variables", n)
	}
}

func TestEnvelopeConstraintCounts(t *testing.T) {
	for _, n := range []int{16, 40, 48} {
		cs := compileEnvelope(t, n)
		variables := cs.GetNbPublicVariables() + cs.GetNbSecretVariables() + cs.GetNbInternalVariables()
		t.Logf("envelope over %d bytes: %d constraints, %d variables", n, cs.GetNbConstraints(), variables)
	}
}

func TestEnvelopeRejectsReportForgery(t *testing.T) {
	forgery := hosttest.ForgeReport(t)
	plaintext := envelopePlaintext(eciesPlaintextBytes)
	ciphertext, _ := forgery.Seal(testSecretTag, testKdfInfo, plaintext)
	recipientLo, recipientHi := forgery.Keys.RecipientPacked()
	ephemeralLo, ephemeralHi := forgery.Keys.EphemeralPacked()
	a := envelopeInputs{
		ephemeralSk: forgery.Keys.EphemeralScalar(),
		recipientPk: forgery.Keys.RecipientUncompressed(),
		recipientLo: recipientLo,
		recipientHi: recipientHi,
		ephemeralLo: ephemeralLo,
		ephemeralHi: ephemeralHi,
		plaintext:   plaintext,
		ciphertext:  ciphertext,
	}.witness()

	err := solveCompiled(t, compileEnvelope(t, eciesPlaintextBytes), a, forgery.Hints(t)...)
	if err == nil {
		t.Fatal("the report forgery was accepted")
	}
	if !strings.Contains(err.Error(), "constraint") {
		t.Fatalf("the forgery failed outside a constraint: %v", err)
	}
	t.Logf("forgery rejected: %v", err)
}
