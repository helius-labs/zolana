// Tested ECIES invariants and diagnostics:
//
//  1. Encryption matches the host implementation, including key-agreement edge
//     cases.
//  2. Empty plaintexts, full blocks, and partial tails produce the expected
//     ciphertext.
//  3. Altered ciphertext and each altered recipient or ephemeral public-key field
//     are rejected.
//  4. The recipient is bound to the public outputs and key derivation, including
//     foreign and mirrored recipients.
//  5. Recipient, ephemeral-scalar, and plaintext inputs are constrained to bytes
//     under adversarial hints and lookups.
//  6. Noncanonical recipient coordinates and the point at infinity are rejected.
//  7. Forged scalar-multiplication reports and mutated hints are rejected.
//  8. The circuit uses one Groth16 commitment with no public variables committed.
//  9. Diagnostic: constraint and variable counts are logged for several plaintext
//     lengths; no count limit is asserted.
package verifiableencryption_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/prover-test/hintattack"
	"zolana/prover/prover-test/hosttest"
	"zolana/prover/prover-test/poseidon"
)

// Invariant 1: Encryption matches the host implementation, including key-agreement edge cases.
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

// Invariant 1: Encryption matches the host implementation, including key-agreement edge cases.
func TestEnvelopeMatchesHostAtEdgeCases(t *testing.T) {
	start := time.Now()
	cs := compileEnvelope(t, eciesPlaintextBytes)
	compiled := time.Since(start)
	cases := hosttest.EdgeCaseKeys()
	for _, edge := range cases {
		t.Run(edge.Name, func(t *testing.T) {
			if err := solveCompiled(t, cs, envelopeAssignmentFor(edge.Keys, eciesPlaintextBytes)); err != nil {
				t.Fatalf("honest envelope rejected: %v", err)
			}
		})
	}
	t.Logf("compiled in %v, solved %d edge cases in %v", compiled, len(cases), time.Since(start)-compiled)
}

// Invariant 2: Empty plaintexts, full blocks, and partial tails produce the expected ciphertext.
func TestEnvelopePlaintextLengths(t *testing.T) {
	for _, n := range []int{0, 1, 15, 17, 31, 32, 33} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			if err := solveCompiled(t, compileEnvelope(t, n), envelopeAssignment(n)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Invariant 3: Altered ciphertext and each altered recipient or ephemeral public-key field are rejected.
func TestEnvelopeRejectsTamperedCiphertext(t *testing.T) {
	a := envelopeAssignment(eciesPlaintextBytes)
	a.Ciphertext[eciesPlaintextBytes-1] = a.Ciphertext[eciesPlaintextBytes-1].(byte) ^ 1
	if err := test.IsSolved(newEnvelopeCircuit(eciesPlaintextBytes), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("a tampered ciphertext was accepted")
	}
}

// Invariant 3: Altered ciphertext and each altered recipient or ephemeral public-key field are rejected.
func TestEnvelopeBindsEachPointField(t *testing.T) {
	cs := compileEnvelope(t, 16)
	if err := solveCompiled(t, cs, envelopeAssignment(16)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"recipient lo", "recipient hi", "ephemeral lo", "ephemeral hi"} {
		t.Run(name, func(t *testing.T) {
			w := envelopeAssignment(16)
			fields := map[string]*frontend.Variable{
				"recipient lo": &w.RecipientLo, "recipient hi": &w.RecipientHi,
				"ephemeral lo": &w.EphemeralLo, "ephemeral hi": &w.EphemeralHi,
			}
			field := fields[name]
			*field = new(big.Int).Add((*field).(*big.Int), big.NewInt(1))
			hintattack.RequireConstraintRejection(t, solveCompiled(t, cs, w))
		})
	}
}

// Invariant 4: The recipient is bound to the public outputs and key derivation, including foreign and mirrored recipients.
// The envelope accepts any valid recipient; callers bind the intended one by
// exposing the recipient and ciphertext as public inputs.
func TestEnvelopeBindsTheRecipientIntoItsPublicOutputs(t *testing.T) {
	other, err := ecdh.P256().NewPrivateKey(append(make([]byte, 31), 0x2c))
	if err != nil {
		t.Fatal(err)
	}
	keys := hosttest.DefaultKeys()
	foreignKeys := hosttest.Keys{RecipientSecret: other, EphemeralSecret: keys.EphemeralSecret}
	registered := envelopeTo(keys, eciesPlaintextBytes)
	foreign := envelopeTo(foreignKeys, eciesPlaintextBytes)

	cs := compileEnvelope(t, eciesPlaintextBytes)
	if err := solveCompiled(t, cs, foreign); err != nil {
		t.Fatalf("a consistent envelope to a foreign recipient was rejected: %v", err)
	}
	if registered.RecipientLo.(*big.Int).Cmp(foreign.RecipientLo.(*big.Int)) == 0 &&
		registered.RecipientHi.(*big.Int).Cmp(foreign.RecipientHi.(*big.Int)) == 0 {
		t.Fatal("the recipient public outputs do not depend on the recipient")
	}
	sameCiphertext := true
	for i := range registered.Ciphertext {
		if registered.Ciphertext[i] != foreign.Ciphertext[i] {
			sameCiphertext = false
		}
	}
	if sameCiphertext {
		t.Fatal("the ciphertext does not depend on the recipient")
	}

	presented := envelopeTo(foreignKeys, eciesPlaintextBytes)
	presented.RecipientLo, presented.RecipientHi = registered.RecipientLo, registered.RecipientHi
	presented.Ciphertext = registered.Ciphertext
	if err := solveCompiled(t, cs, presented); err == nil {
		t.Fatal("an envelope to a foreign recipient matched the registered recipient's public outputs")
	}
}

// Invariant 4: The recipient is bound to the public outputs and key derivation, including foreign and mirrored recipients.
func TestEnvelopeBoundaryForeignRecipientWithConsistentFields(t *testing.T) {
	cs := compileEnvelope(t, eciesPlaintextBytes)
	keys := hosttest.DefaultKeys()
	other, err := ecdh.P256().NewPrivateKey(append(make([]byte, 31), 0x2c))
	if err != nil {
		t.Fatal(err)
	}
	keyedTo := keys.RecipientUncompressed()
	presented := [65]byte(other.PublicKey().Bytes())

	honest := presentedEnvelope{keys.EphemeralSecret, presented, hosttest.SharedX(t, keys.EphemeralSecret, presented)}
	if err := solveCompiled(t, cs, honest.witness(t)); err != nil {
		t.Fatalf("honest envelope to the presented recipient rejected: %v", err)
	}
	forged := presentedEnvelope{keys.EphemeralSecret, presented, hosttest.SharedX(t, keys.EphemeralSecret, keyedTo)}
	hintattack.RequireConstraintRejection(t, solveCompiled(t, cs, forged.witness(t)))
}

// Invariant 4: The recipient is bound to the public outputs and key derivation, including foreign and mirrored recipients.
func TestEnvelopeBoundaryMirroredRecipient(t *testing.T) {
	cs := compileEnvelope(t, eciesPlaintextBytes)
	keys := hosttest.DefaultKeys()
	keyedTo := keys.RecipientUncompressed()
	presented := mirroredPoint(keyedTo)
	shared := hosttest.SharedX(t, keys.EphemeralSecret, keyedTo)
	if !bytes.Equal(shared, hosttest.SharedX(t, keys.EphemeralSecret, presented)) {
		t.Fatal("the mirrored recipient changes the shared x")
	}

	honest := presentedEnvelope{keys.EphemeralSecret, presented, shared}.witness(t)
	if err := solveCompiled(t, cs, honest); err != nil {
		t.Fatalf("honest envelope to the mirrored recipient rejected: %v", err)
	}
	forged := presentedEnvelope{keys.EphemeralSecret, presented, shared}.witness(t)
	forged.Ciphertext = presentedEnvelope{keys.EphemeralSecret, keyedTo, shared}.witness(t).Ciphertext
	hintattack.RequireConstraintRejection(t, solveCompiled(t, cs, forged))
}

// Invariant 5: Recipient, ephemeral-scalar, and plaintext inputs are constrained to bytes under adversarial hints and lookups.
func TestEnvelopeBoundaryRecipientByteRangeCheck(t *testing.T) {
	recipient := func(a *envelopeCircuit) []frontend.Variable { return a.RecipientPk[:] }
	requireEnvelopeRangeChecks(t, []carriedByte{
		{"x byte 5", recipient, 5},
		{"y byte 40", recipient, 40},
	})
}

// Invariant 5: Recipient, ephemeral-scalar, and plaintext inputs are constrained to bytes under adversarial hints and lookups.
func TestEnvelopeBoundaryEphemeralByteRangeCheck(t *testing.T) {
	ephemeral := func(a *envelopeCircuit) []frontend.Variable { return a.EphemeralSk[:] }
	requireEnvelopeRangeChecks(t, []carriedByte{
		{"scalar byte 5", ephemeral, 5},
		{"scalar byte 29", ephemeral, 29},
	})
}

// Invariant 5: Recipient, ephemeral-scalar, and plaintext inputs are constrained to bytes under adversarial hints and lookups.
func TestEnvelopeBoundaryPlaintextByteLookup(t *testing.T) {
	const position = 7
	keys := hosttest.DefaultKeys()
	plaintext := envelopePlaintext(eciesPlaintextBytes)
	for _, row := range []struct {
		name       string
		substitute byte
	}{
		{"ciphertext of byte zero", 0},
		{"ciphertext of the honest byte", plaintext[position]},
	} {
		t.Run(row.name, func(t *testing.T) {
			cs := compileEnvelope(t, eciesPlaintextBytes)
			substituted := hintattack.SubstituteOutOfRangeLookups(t, cs, uint64(row.substitute))
			skip := hintattack.SkipMissingLookupQueries(t)
			if err := solveCompiled(t, cs, envelopeAssignmentFor(keys, eciesPlaintextBytes), skip); err != nil {
				t.Fatalf("honest envelope rejected: %v", err)
			}
			if n := substituted.Load(); n != 0 {
				t.Fatalf("the honest envelope substituted %d lookups", n)
			}

			presented := slices.Clone(plaintext)
			presented[position] = row.substitute
			ciphertext, _ := keys.Encrypt(testSecretTag, testKdfInfo, presented)
			a := envelopeAssignmentFor(keys, eciesPlaintextBytes)
			a.Plaintext[position] = 256
			for i, b := range ciphertext {
				a.Ciphertext[i] = b
			}
			err := solveCompiled(t, cs, a, skip)
			if n := substituted.Load(); n != 1 {
				t.Errorf("substituted %d out-of-range lookups, want the one plaintext byte", n)
			}
			hintattack.RequireConstraintRejection(t, err)
		})
	}
}

// Invariant 6: Noncanonical recipient coordinates and the point at infinity are rejected.
func TestEnvelopeBoundaryNonCanonicalRecipient(t *testing.T) {
	cs := compileEnvelope(t, eciesPlaintextBytes)
	ephemeral := hosttest.DefaultKeys().EphemeralSecret
	for _, row := range hosttest.NonCanonicalRecipients(t) {
		t.Run(row.Name, func(t *testing.T) {
			shared := hosttest.SharedX(t, ephemeral, row.Canonical)
			if err := solveCompiled(t, cs, presentedEnvelope{ephemeral, row.Canonical, shared}.witness(t)); err != nil {
				t.Fatalf("canonical recipient rejected: %v", err)
			}
			forged := presentedEnvelope{ephemeral, row.Presented, shared}
			hintattack.RequireConstraintRejection(t, solveCompiled(t, cs, forged.witness(t)))
		})
	}
}

// Invariant 6: Noncanonical recipient coordinates and the point at infinity are rejected.
func TestEnvelopeRejectsInfinityRecipient(t *testing.T) {
	keys := hosttest.DefaultKeys()
	plaintext := envelopePlaintext(eciesPlaintextBytes)
	recipientLo, recipientHi := hosttest.PackCompressed([33]byte{0x02})
	ephemeralLo, ephemeralHi := keys.EphemeralPacked()
	sharedLo, sharedHi := hosttest.PackShared([32]byte{})
	sharedSecret, err := poseidon.Hash([]*big.Int{
		ve.SecretTagValue(testSecretTag),
		sharedLo, sharedHi,
		ephemeralLo, ephemeralHi,
		recipientLo, recipientHi,
	})
	if err != nil {
		t.Fatal(err)
	}
	key, nonce := hosttest.KeySchedule(sharedSecret, testKdfInfo)
	a := envelopeInputs{
		ephemeralSk: keys.EphemeralScalar(),
		recipientPk: [65]byte{0x04},
		recipientLo: recipientLo,
		recipientHi: recipientHi,
		ephemeralLo: ephemeralLo,
		ephemeralHi: ephemeralHi,
		plaintext:   plaintext,
		ciphertext:  hosttest.CTR(key, nonce, plaintext),
	}.witness()

	hintattack.RequireConstraintRejection(t, solveCompiled(t, compileEnvelope(t, eciesPlaintextBytes), a))
}

// Invariant 7: Forged scalar-multiplication reports and mutated hints are rejected.
func TestEnvelopeRejectsReportForgery(t *testing.T) {
	cs := compileEnvelope(t, eciesPlaintextBytes)
	for _, forgery := range hosttest.ForgeReports(t) {
		t.Run(forgery.Name, func(t *testing.T) {
			plaintext := envelopePlaintext(eciesPlaintextBytes)
			ciphertext, _ := forgery.Encrypt(testSecretTag, testKdfInfo, plaintext)
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

			err := solveCompiled(t, cs, a, forgery.Hints(t)...)
			if err == nil {
				t.Fatal("the report forgery was accepted")
			}
			if !strings.Contains(err.Error(), "constraint") {
				t.Fatalf("the forgery failed outside a constraint: %v", err)
			}
			t.Logf("forgery rejected: %v", err)
		})
	}
}

// Invariant 7: Forged scalar-multiplication reports and mutated hints are rejected.
func TestEnvelopeRejectsHintAttacks(t *testing.T) {
	cs := compileEnvelope(t, eciesPlaintextBytes)
	defaults := hosttest.DefaultKeys()
	recipient := new(big.Int).SetBytes(defaults.RecipientSecret.Bytes())
	minusOne := new(big.Int).Sub(elliptic.P256().Params().N, big.NewInt(1))
	for _, row := range []struct {
		name string
		keys hosttest.Keys
	}{
		{"default keys", defaults},
		{"ephemeral scalar minus one", hosttest.NewKeys(recipient, minusOne)},
	} {
		assignment := envelopeAssignmentFor(row.keys, eciesPlaintextBytes)
		t.Run(row.name, func(t *testing.T) {
			hintattack.RunHintAttacks(t, cs, func(opts ...solver.Option) error {
				return solveCompiled(t, cs, assignment, opts...)
			})
		})
	}
}

// Invariant 8: The circuit uses one Groth16 commitment with no public variables committed.
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

// Diagnostic 9: constraint and variable counts are logged for several plaintext lengths; no count limit is asserted.
func TestEnvelopeConstraintCounts(t *testing.T) {
	for _, n := range []int{16, 40, 48} {
		cs := compileEnvelope(t, n)
		variables := cs.GetNbPublicVariables() + cs.GetNbSecretVariables() + cs.GetNbInternalVariables()
		t.Logf("envelope over %d bytes: %d constraints, %d variables", n, cs.GetNbConstraints(), variables)
	}
}

// Test circuits and shared helpers.

var boundaryEphemeralScalar = new(big.Int).SetBytes([]byte("ephemeral scalar for the merge!!"))

func boundaryKeys() hosttest.Keys {
	recipient := new(big.Int).SetBytes(hosttest.DefaultKeys().RecipientSecret.Bytes())
	return hosttest.NewKeys(recipient, boundaryEphemeralScalar)
}

func mirroredPoint(point [65]byte) [65]byte {
	y := new(big.Int).SetBytes(point[33:65])
	return hosttest.UncompressedPoint(new(big.Int).SetBytes(point[1:33]), y.Sub(elliptic.P256().Params().P, y))
}

type presentedEnvelope struct {
	ephemeral   *ecdh.PrivateKey
	recipientPk [65]byte
	sharedX     []byte
}

func (e presentedEnvelope) witness(t *testing.T) *envelopeCircuit {
	t.Helper()
	plaintext := envelopePlaintext(eciesPlaintextBytes)
	recipientLo, recipientHi := hosttest.PackCompressed(hosttest.CompressP256(e.recipientPk[:]))
	ephemeralLo, ephemeralHi := hosttest.PackCompressed(hosttest.CompressP256(e.ephemeral.PublicKey().Bytes()))
	sharedLo, sharedHi := hosttest.PackShared([32]byte(e.sharedX))
	sharedSecret, err := poseidon.Hash([]*big.Int{
		ve.SecretTagValue(testSecretTag),
		sharedLo, sharedHi,
		ephemeralLo, ephemeralHi,
		recipientLo, recipientHi,
	})
	if err != nil {
		t.Fatal(err)
	}
	key, nonce := hosttest.KeySchedule(sharedSecret, testKdfInfo)
	return envelopeInputs{
		ephemeralSk: [32]byte(e.ephemeral.Bytes()),
		recipientPk: e.recipientPk,
		recipientLo: recipientLo,
		recipientHi: recipientHi,
		ephemeralLo: ephemeralLo,
		ephemeralHi: ephemeralHi,
		plaintext:   plaintext,
		ciphertext:  hosttest.CTR(key, nonce, plaintext),
	}.witness()
}

type carriedByte struct {
	name  string
	bytes func(*envelopeCircuit) []frontend.Variable
	k     int
}

func requireEnvelopeRangeChecks(t *testing.T, carries []carriedByte) {
	t.Helper()
	cs := compileEnvelope(t, eciesPlaintextBytes)
	keys := boundaryKeys()
	for _, prover := range hosttest.RangeCheckProvers(t) {
		t.Run(prover.Name, func(t *testing.T) {
			if err := solveCompiled(t, cs, envelopeAssignmentFor(keys, eciesPlaintextBytes), prover.Options...); err != nil {
				t.Fatalf("honest envelope rejected: %v", err)
			}
			for _, carry := range carries {
				t.Run(carry.name, func(t *testing.T) {
					a := envelopeAssignmentFor(keys, eciesPlaintextBytes)
					hosttest.CarryIntoByte(t, carry.bytes(a), carry.k)
					hintattack.RequireConstraintRejection(t, solveCompiled(t, cs, a, prover.Options...))
				})
			}
		})
	}
}

func envelopeAssignmentFor(keys hosttest.Keys, n int) *envelopeCircuit {
	plaintext := envelopePlaintext(n)
	ciphertext, _ := keys.Encrypt(testSecretTag, testKdfInfo, plaintext)
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
	encrypted := ve.Envelope{
		SecretTag:   testSecretTag,
		KdfInfo:     testKdfInfo,
		EphemeralSk: c.EphemeralSk,
		RecipientPk: c.RecipientPk,
		Plaintext:   c.Plaintext,
	}.Encrypt(api)
	api.AssertIsEqual(encrypted.RecipientLo, c.RecipientLo)
	api.AssertIsEqual(encrypted.RecipientHi, c.RecipientHi)
	api.AssertIsEqual(encrypted.EphemeralLo, c.EphemeralLo)
	api.AssertIsEqual(encrypted.EphemeralHi, c.EphemeralHi)
	for i, b := range encrypted.Ciphertext {
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
	return envelopeTo(hosttest.DefaultKeys(), n)
}

func envelopeTo(keys hosttest.Keys, n int) *envelopeCircuit {
	plaintext := envelopePlaintext(n)
	ciphertext, _ := keys.Encrypt(testSecretTag, testKdfInfo, plaintext)
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
