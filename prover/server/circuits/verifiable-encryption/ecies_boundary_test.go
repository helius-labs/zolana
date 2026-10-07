package verifiableencryption_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark/frontend"

	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/prover-test/hintattack"
	"zolana/prover/prover-test/hosttest"
	"zolana/prover/prover-test/poseidon"
)

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

func TestEnvelopeBoundaryRecipientByteRangeCheck(t *testing.T) {
	recipient := func(a *envelopeCircuit) []frontend.Variable { return a.RecipientPk[:] }
	requireEnvelopeRangeChecks(t, []carriedByte{
		{"x byte 5", recipient, 5},
		{"y byte 40", recipient, 40},
	})
}

func TestEnvelopeBoundaryEphemeralByteRangeCheck(t *testing.T) {
	ephemeral := func(a *envelopeCircuit) []frontend.Variable { return a.EphemeralSk[:] }
	requireEnvelopeRangeChecks(t, []carriedByte{
		{"scalar byte 5", ephemeral, 5},
		{"scalar byte 29", ephemeral, 29},
	})
}

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
