package merge_test

import (
	"crypto/ecdh"
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
	"zolana/prover/prover-test/hosttest"
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

func TestMergeEnvelopeRejectsForeignRecipient(t *testing.T) {
	other, err := ecdh.P256().NewPrivateKey(append(make([]byte, 31), 0x2c))
	if err != nil {
		t.Fatal(err)
	}
	a := buildValidWitness(t)
	for i, b := range other.PublicKey().Bytes() {
		a.ViewingPk[i] = b
	}
	assertDefaultUnsat(t, a, "a foreign recipient key")
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

func TestMergeEnvelopeRejectsReportForgery(t *testing.T) {
	cs := compiledDefaultMerge(t)
	for _, forgery := range hosttest.ForgeReports(t) {
		t.Run(forgery.Name, func(t *testing.T) {
			recipientLo, recipientHi := forgery.Keys.RecipientPacked()
			ephemeralLo, ephemeralHi := forgery.Keys.EphemeralPacked()
			forged := func(t testing.TB, plaintext []byte) hostEnvelope {
				ciphertext, secret := forgery.Encrypt(mergeshared.MergeSecretTag, mergeshared.MergeKdfInfo, plaintext)
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
