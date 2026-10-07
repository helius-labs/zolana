package merge_test

import (
	"crypto/ecdh"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	merge "zolana/prover/circuits/spp_merge"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/prover-test/hintattack"
	"zolana/prover/prover-test/hosttest"
	"zolana/prover/prover-test/poseidon"
)

var (
	defaultMergeCSOnce sync.Once
	defaultMergeCS     constraint.ConstraintSystem
	defaultMergeCSErr  error
)

func compileMerge(t *testing.T, circuit frontend.Circuit) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cs
}

func compiledDefaultMerge(t *testing.T) constraint.ConstraintSystem {
	t.Helper()
	defaultMergeCSOnce.Do(func() {
		defaultMergeCS, defaultMergeCSErr = frontend.Compile(
			ecc.BN254.ScalarField(),
			r1cs.NewBuilder,
			merge.NewMergeCircuit(defaultFixtureInputs),
			frontend.WithCompressThreshold(300),
		)
	})
	if defaultMergeCSErr != nil {
		t.Fatalf("compile: %v", defaultMergeCSErr)
	}
	return defaultMergeCS
}

func solveMerge(t *testing.T, cs constraint.ConstraintSystem, assignment frontend.Circuit, opts ...solver.Option) error {
	t.Helper()
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return cs.IsSolved(w, opts...)
}

func assertDefaultUnsat(t *testing.T, assignment *merge.Circuit, what string) {
	t.Helper()
	if err := test.IsSolved(merge.NewMergeCircuit(defaultFixtureInputs), assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatalf("accepted %s", what)
	}
}

func TestMergeEnvelopeRejectsTamperedCiphertext(t *testing.T) {
	for _, index := range []int{0, mergeshared.MergeHeadChunkCiphertextBytes - 1, mergeshared.MergeHeadChunkCiphertextBytes, mergeshared.MergeCiphertextBytes - 1} {
		f := buildMergeFixture(t, mergeFixtureOptions{})
		tampered := append([]byte(nil), f.envelope.ciphertext...)
		tampered[index] ^= 1
		f.envelope.ciphertext = tampered
		refreshDefaultPublicInputHash(t, f)
		assertDefaultUnsat(t, f.defaultCircuit(), "a tampered ciphertext byte")
	}
}

// The circuit accepts an envelope to any valid recipient. What keeps a merge on
// the registered viewing key is the public input hash: the program recomputes
// it from the registry key (merge_rejects_a_proof_encrypted_to_a_key_other_than_the_registered_one
// in program-tests/shielded-pool/tests/merge/functional.rs).
func TestMergeEnvelopeBindsTheRecipientIntoThePublicInput(t *testing.T) {
	other, err := ecdh.P256().NewPrivateKey(append(make([]byte, 31), 0x2c))
	if err != nil {
		t.Fatal(err)
	}
	foreignKeys := hosttest.Keys{RecipientSecret: other, EphemeralSecret: hosttest.DefaultKeys().EphemeralSecret}
	toForeign := func(t testing.TB, plaintext []byte, firstNullifier *big.Int) hostEnvelope {
		return envelopeTo(foreignKeys, plaintext, firstNullifier)
	}
	cs := compiledDefaultMerge(t)
	registered := buildMergeFixture(t, mergeFixtureOptions{})
	foreign := buildMergeFixture(t, mergeFixtureOptions{encrypt: toForeign})

	if err := solveMerge(t, cs, foreign.defaultCircuit()); err != nil {
		t.Fatalf("a consistent envelope to a foreign recipient was rejected: %v", err)
	}
	if registered.envelope.recipientLo.Cmp(foreign.envelope.recipientLo) == 0 {
		t.Fatal("the recipient public element does not depend on the recipient")
	}
	if registered.publicInputHash.Cmp(foreign.publicInputHash) == 0 {
		t.Fatal("the public input hash does not depend on the recipient")
	}

	presented := foreign.defaultCircuit()
	presented.PublicInputHash = registered.publicInputHash
	if err := solveMerge(t, cs, presented); err == nil {
		t.Fatal("an envelope to a foreign recipient verified against the registered key's public input hash")
	}
}

func TestMergeEnvelopeRejectsOffCurveViewingKey(t *testing.T) {
	a := buildValidWitness(t)
	// Bit 1 of y keeps the parity, so the compressed recipient and the public
	// input hash stay those of the honest key and only the curve check can fail.
	a.ViewingPk[ve.UncompressedPointBytes-1] = a.ViewingPk[ve.UncompressedPointBytes-1].(byte) ^ 0x02
	err := solveMerge(t, compiledDefaultMerge(t), a)
	if err == nil {
		t.Fatal("an off-curve viewing key was accepted")
	}
	if !strings.Contains(err.Error(), "constraint") {
		t.Fatalf("the off-curve viewing key failed outside a constraint: %v", err)
	}
}

func TestMergeEnvelopeRejectsZeroEphemeralKey(t *testing.T) {
	a := buildValidWitness(t)
	for i := range a.EphemeralSk {
		a.EphemeralSk[i] = 0
	}
	err := solveMerge(t, compiledDefaultMerge(t), a)
	if err == nil {
		t.Fatal("a zero ephemeral key was accepted")
	}
	if !strings.Contains(err.Error(), "constraint") {
		t.Fatalf("the zero ephemeral key failed outside a constraint: %v", err)
	}
}

func TestMergeEnvelopeRejectsNullifierDerivedBlinding(t *testing.T) {
	a := buildDefaultWitness(t, mergeFixtureOptions{legacyBlinding: true})
	assertDefaultUnsat(t, a, "an output blinding derived from the nullifier secret")
}

func TestMergeEnvelopeRejectsNonUncompressedPrefix(t *testing.T) {
	a := buildValidWitness(t)
	a.ViewingPk[0] = 0x03
	assertDefaultUnsat(t, a, "a viewing key without the 0x04 prefix")
}

func TestMergeEnvelopeRejectsInfinityRecipient(t *testing.T) {
	keys := hosttest.DefaultKeys()
	recipientLo, recipientHi := hosttest.PackCompressed([33]byte{0x02})
	ephemeralLo, ephemeralHi := keys.EphemeralPacked()
	sharedLo, sharedHi := hosttest.PackShared([32]byte{})
	infinity := func(t testing.TB, plaintext []byte, firstNullifier *big.Int) hostEnvelope {
		t.Helper()
		sharedSecret, err := poseidon.Hash([]*big.Int{
			ve.SecretTagValue(mergeshared.MergeSecretTag),
			sharedLo, sharedHi,
			ephemeralLo, ephemeralHi,
			recipientLo, recipientHi,
			firstNullifier,
		})
		if err != nil {
			t.Fatal(err)
		}
		key, nonce := hosttest.KeySchedule(sharedSecret, mergeshared.MergeKdfInfo)
		return hostEnvelope{
			recipientPk:  [65]byte{0x04},
			recipientLo:  recipientLo,
			recipientHi:  recipientHi,
			ephemeralSk:  keys.EphemeralScalar(),
			ephemeralLo:  ephemeralLo,
			ephemeralHi:  ephemeralHi,
			ciphertext:   hosttest.CTR(key, nonce, plaintext),
			sharedSecret: sharedSecret,
		}
	}
	f := buildMergeFixture(t, mergeFixtureOptions{encrypt: infinity})
	hintattack.RequireConstraintRejection(t, solveMerge(t, compiledDefaultMerge(t), f.defaultCircuit()))
}

func TestMergeEnvelopeRejectsReportForgery(t *testing.T) {
	cs := compiledDefaultMerge(t)
	for _, forgery := range hosttest.ForgeReports(t) {
		t.Run(forgery.Name, func(t *testing.T) {
			recipientLo, recipientHi := forgery.Keys.RecipientPacked()
			ephemeralLo, ephemeralHi := forgery.Keys.EphemeralPacked()
			forged := func(t testing.TB, plaintext []byte, firstNullifier *big.Int) hostEnvelope {
				ciphertext, secret := forgery.EncryptWithContext(mergeshared.MergeSecretTag, mergeshared.MergeKdfInfo, plaintext, firstNullifier)
				return hostEnvelope{
					recipientPk:  forgery.Keys.RecipientUncompressed(),
					recipientLo:  recipientLo,
					recipientHi:  recipientHi,
					ephemeralSk:  forgery.Keys.EphemeralScalar(),
					ephemeralLo:  ephemeralLo,
					ephemeralHi:  ephemeralHi,
					ciphertext:   ciphertext,
					sharedSecret: secret,
				}
			}
			f := buildMergeFixture(t, mergeFixtureOptions{encrypt: forged})

			err := solveMerge(t, cs, f.defaultCircuit(), forgery.Hints(t)...)
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

func TestMergeCompiledSolvesHonestWitness(t *testing.T) {
	if err := solveMerge(t, compiledDefaultMerge(t), buildValidWitness(t)); err != nil {
		t.Fatalf("compiled default merge rejected the honest witness: %v", err)
	}
}

func TestMergeCommitmentCounts(t *testing.T) {
	cs := compiledDefaultMerge(t)
	t.Logf("merge %dx1 default: %d constraints, %d BSB22 commitments", defaultFixtureInputs, cs.GetNbConstraints(), len(cs.GetCommitments().CommitmentIndexes()))
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok || len(commitments) != 1 {
		t.Fatalf("default rail: want one Groth16 commitment, got %v", cs.GetCommitments())
	}
	if n := len(commitments[0].PublicAndCommitmentCommitted); n != 0 {
		t.Fatalf("default rail: the commitment covers %d public variables", n)
	}

	ring := compileMerge(t, merge.NewMergeRingCircuit(defaultFixtureInputs))
	t.Logf("merge %dx1 ring: %d constraints, %d BSB22 commitments", defaultFixtureInputs, ring.GetNbConstraints(), len(ring.GetCommitments().CommitmentIndexes()))
	if n := len(ring.GetCommitments().CommitmentIndexes()); n != 0 {
		t.Fatalf("ring rail: want no commitments, got %d", n)
	}
}
