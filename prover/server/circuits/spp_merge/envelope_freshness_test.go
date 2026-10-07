package merge_test

import (
	"bytes"
	"math/big"
	"testing"

	mergeshared "zolana/prover/circuits/spp_merge/shared"
	"zolana/prover/prover-test/hintattack"
	"zolana/prover/prover-test/hosttest"
	"zolana/prover/prover-test/spp/protocol"
)

func encryptWithContext(context func(firstNullifier *big.Int) *big.Int) func(testing.TB, []byte, *big.Int) hostEnvelope {
	return func(t testing.TB, plaintext []byte, firstNullifier *big.Int) hostEnvelope {
		t.Helper()
		return envelopeTo(hosttest.DefaultKeys(), plaintext, context(firstNullifier))
	}
}

func withoutFirstNullifier(*big.Int) *big.Int { return nil }

func fixtureOutputAmount(f *mergeWitnessFixture) *big.Int {
	sum := new(big.Int)
	for _, in := range f.inputs {
		sum.Add(sum, in.Amount.(*big.Int))
	}
	return sum
}

func fixtureNullifier(t *testing.T, f *mergeWitnessFixture, utxoHash, blinding *big.Int) *big.Int {
	t.Helper()
	nullifier, err := protocol.Nullifier(utxoHash, blinding, f.userNullifierSecret)
	if err != nil {
		t.Fatal(err)
	}
	return nullifier
}

func remergeOutput(t *testing.T, merged *mergeWitnessFixture, options mergeFixtureOptions) *mergeWitnessFixture {
	t.Helper()
	options.outputTreeID = fixtureInputTreeID
	options.realInputs = []fixtureInput{{amount: fixtureOutputAmount(merged), blinding: merged.outputBlinding}}
	remerge := buildMergeFixture(t, options)
	spent := fixtureNullifier(t, merged, merged.public.OutputHash.(*big.Int), merged.outputBlinding)
	if remerge.public.Nullifiers[0].(*big.Int).Cmp(spent) != 0 {
		t.Fatal("the re-merge does not spend the merged output")
	}
	return remerge
}

func TestMergeEnvelopeReusedEphemeralKeyStaysFresh(t *testing.T) {
	cs := compiledDefaultMerge(t)
	first := buildMergeFixture(t, mergeFixtureOptions{})
	second := buildMergeFixture(t, mergeFixtureOptions{realInputs: []fixtureInput{
		{amount: big.NewInt(5), blinding: big.NewInt(0x3333)},
		{amount: big.NewInt(7), blinding: big.NewInt(0x4444)},
	}})
	for _, f := range []*mergeWitnessFixture{first, second} {
		if err := solveMerge(t, cs, f.defaultCircuit()); err != nil {
			t.Fatalf("the compiled default merge rejected an honest envelope: %v", err)
		}
	}

	if first.envelope.ephemeralSk != second.envelope.ephemeralSk || first.envelope.recipientPk != second.envelope.recipientPk {
		t.Fatal("the merges do not share the ephemeral key and the recipient")
	}
	if first.public.Nullifiers[0].(*big.Int).Cmp(second.public.Nullifiers[0].(*big.Int)) == 0 {
		t.Fatal("the merges share the first nullifier")
	}
	if fixtureOutputAmount(first).Cmp(fixtureOutputAmount(second)) != 0 {
		t.Fatal("the merges encrypt different plaintexts")
	}

	firstKey, firstNonce := hosttest.KeySchedule(first.envelope.sharedSecret, mergeshared.MergeKdfInfo)
	secondKey, secondNonce := hosttest.KeySchedule(second.envelope.sharedSecret, mergeshared.MergeKdfInfo)
	for _, shared := range []struct {
		name string
		same bool
	}{
		{"shared secret", first.envelope.sharedSecret.Cmp(second.envelope.sharedSecret) == 0},
		{"AES key", firstKey == secondKey},
		{"nonce", firstNonce == secondNonce},
		{"ciphertext", bytes.Equal(first.envelope.ciphertext, second.envelope.ciphertext)},
		{"output blinding", first.outputBlinding.Cmp(second.outputBlinding) == 0},
		{"output hash", first.public.OutputHash.(*big.Int).Cmp(second.public.OutputHash.(*big.Int)) == 0},
	} {
		if shared.same {
			t.Errorf("two merges under one ephemeral key share the %s", shared.name)
		}
	}
}

func TestMergeEnvelopeRemergeUnderReusedEphemeralKeyKeepsItsOutput(t *testing.T) {
	cs := compiledDefaultMerge(t)
	merged := buildMergeFixture(t, mergeFixtureOptions{outputTreeID: fixtureInputTreeID})
	remerge := remergeOutput(t, merged, mergeFixtureOptions{})
	if err := solveMerge(t, cs, remerge.defaultCircuit()); err != nil {
		t.Fatalf("the compiled default merge rejected the re-merge: %v", err)
	}

	if remerge.envelope.ephemeralSk != merged.envelope.ephemeralSk {
		t.Fatal("the re-merge does not reuse the ephemeral key")
	}
	outputHash := remerge.public.OutputHash.(*big.Int)
	if outputHash.Cmp(merged.public.OutputHash.(*big.Int)) == 0 {
		t.Fatal("the re-merge recreated its input leaf")
	}
	published := remerge.public.Nullifiers[0].(*big.Int)
	if fixtureNullifier(t, remerge, outputHash, remerge.outputBlinding).Cmp(published) == 0 {
		t.Fatal("the re-merge output's nullifier is the one the re-merge publishes")
	}

	legacy := mergeFixtureOptions{outputTreeID: fixtureInputTreeID, encrypt: encryptWithContext(withoutFirstNullifier)}
	legacyMerged := buildMergeFixture(t, legacy)
	legacyRemerge := remergeOutput(t, legacyMerged, legacy)
	if legacyRemerge.public.OutputHash.(*big.Int).Cmp(legacyMerged.public.OutputHash.(*big.Int)) != 0 {
		t.Fatal("without the first nullifier the re-merge does not recreate its input leaf; the scenario does not reach the burn")
	}
}

func TestMergeEnvelopeRejectsSharedSecretWithoutFirstNullifier(t *testing.T) {
	cs := compiledDefaultMerge(t)
	for _, row := range []struct {
		name    string
		context func(firstNullifier *big.Int) *big.Int
	}{
		{"without the first nullifier", withoutFirstNullifier},
		{"over another value", func(firstNullifier *big.Int) *big.Int {
			return new(big.Int).Add(firstNullifier, big.NewInt(1))
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := buildMergeFixture(t, mergeFixtureOptions{encrypt: encryptWithContext(row.context)})
			hintattack.RequireConstraintRejection(t, solveMerge(t, cs, f.defaultCircuit()))
		})
	}
}
