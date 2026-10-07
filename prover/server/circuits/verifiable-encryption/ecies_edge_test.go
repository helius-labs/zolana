package verifiableencryption_test

import (
	"math/big"
	"strings"
	"testing"
	"time"

	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/prover-test/hosttest"
	"zolana/prover/prover-test/poseidon"
)

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

	err = solveCompiled(t, compileEnvelope(t, eciesPlaintextBytes), a)
	if err == nil {
		t.Fatal("an envelope to the infinity recipient was accepted")
	}
	if !strings.Contains(err.Error(), "constraint") {
		t.Fatalf("the infinity recipient failed outside a constraint: %v", err)
	}
	t.Logf("rejected: %v", err)
}
