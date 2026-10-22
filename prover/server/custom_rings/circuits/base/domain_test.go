package base_test

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// Distinct tags keep a hash of one role from opening as another.
func TestRingDomainsAreTheAsciiTags(t *testing.T) {
	seen := map[uint64]string{
		shared.OutputBlindingDomainV1:     "TXOB",
		shared.OutputBlindingSeedDomainV1: "TXOS",
		shared.PrivateTxBlindingDomainV1:  "TXPB",
	}
	for _, domain := range []struct {
		tag   string
		value uint64
	}{
		{"CRAU", base.AuditStatementDomain},
		{"CRAS", base.PackedSlotSecretDomain},
		{"CRDS", base.DeliveredSlotSecretDomain},
		{"CRRC", base.ConfidentialRingSecretDomain},
		{"CRRA", base.AnonymousRingSecretDomain},
		{"CRIK", base.InboxKeyDomain},
		{"CRIT", base.InboxTagDomain},
		{"CRPK", base.PairKeyDomain},
		{"CRPT", base.PairTagDomain},
		{"CRSC", base.SenderCommitmentDomain},
		{"CROD", base.DisclosurePadDomain},
		{"CRPO", base.PolicyStatementDomain},
		{"CRTB", base.PolicyTableDomain},
		{"CRQW", base.QueueWriteDomain},
		{"CRAP", base.ApplyRecordsDomain},
		{"CRRG", base.RegisterKeyDomain},
		{"CRDB", base.DepositBlindingDomain},
		{"CR_S", base.DomSepCRShared},
		{"CR_MD", base.MergeDisclosureDomain},
		{"TXRB", shared.RingOutputBlindingDomainV1},
	} {
		if want := new(big.Int).SetBytes([]byte(domain.tag)).Uint64(); domain.value != want {
			t.Errorf("%s = %#x, want %#x", domain.tag, domain.value, want)
		}
		if other, taken := seen[domain.value]; taken {
			t.Errorf("%s shares its value with %s", domain.tag, other)
		}
		seen[domain.value] = domain.tag
	}
}

type ringTagVectors struct {
	Constants struct {
		EpochSlots  int `json:"epoch_slots"`
		JInbox      int `json:"j_inbox"`
		JPair       int `json:"j_pair"`
		KPairEpochs int `json:"k_pair_epochs"`
		TagLen      int `json:"tag_len"`
		BodyLen     int `json:"body_len"`
	} `json:"constants"`
	RingProgramAddress string            `json:"ring_program_id"`
	RingProgramID      string            `json:"ring_id"`
	ViewingPk          string            `json:"viewing_pk"`
	InboxKey           string            `json:"inbox_key"`
	InboxTags          []streamTagVector `json:"inbox_tags"`
	FirstContactSecret string            `json:"first_contact_secret"`
	PairKey            string            `json:"pair_key"`
	PairTags           []streamTagVector `json:"pair_tags"`
	Low248             []struct {
		Value string `json:"value"`
		Tag   string `json:"tag"`
	} `json:"low248"`
}

type streamTagVector struct {
	Epoch uint64 `json:"epoch"`
	Index int    `json:"index"`
	Tag   string `json:"tag"`
}

type ringTagsCircuit struct {
	RingProgramAddress [32]frontend.Variable
	RingProgramID      frontend.Variable
	ViewingPk          [33]frontend.Variable
	InboxKey           frontend.Variable
	InboxTags          []streamTagWires
	FirstContactSecret frontend.Variable
	PairKey            frontend.Variable
	PairTags           []streamTagWires
	Low248             []low248Wires
}

type streamTagWires struct{ Epoch, Index, Tag frontend.Variable }

type low248Wires struct{ Value, Tag frontend.Variable }

func (c *ringTagsCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	api.AssertIsEqual(gadget.HashBytes(api, c.RingProgramAddress[:]), c.RingProgramID)
	inboxKey := base.InboxKey(api, c.RingProgramID, [2]frontend.Variable(gadget.PackBytesBE(api, c.ViewingPk[:])))
	api.AssertIsEqual(inboxKey, c.InboxKey)
	for _, tag := range c.InboxTags {
		api.AssertIsEqual(base.TagField(api, rc, base.InboxTagDigest(api, inboxKey, tag.Epoch, tag.Index)), tag.Tag)
	}
	pairKey := base.PairKey(api, c.FirstContactSecret)
	api.AssertIsEqual(pairKey, c.PairKey)
	for _, tag := range c.PairTags {
		api.AssertIsEqual(base.TagField(api, rc, base.PairTagDigest(api, pairKey, tag.Epoch, tag.Index)), tag.Tag)
	}
	for _, low := range c.Low248 {
		api.AssertIsEqual(base.TagField(api, rc, low.Value), low.Tag)
	}
	return nil
}

func TestRingTagsMatchRustVectors(t *testing.T) {
	var vectors ringTagVectors
	readRingVector(t, "ring-tags.json", &vectors)
	constants := vectors.Constants
	if constants.EpochSlots != base.EpochSlots || constants.JInbox != base.JInbox || constants.JPair != base.JPair ||
		constants.KPairEpochs != base.KPairEpochs || constants.TagLen != base.TagLen || constants.BodyLen != base.BodyLen {
		t.Fatalf("stream constants drifted from the Rust vector, got %+v", constants)
	}
	witness := &ringTagsCircuit{
		RingProgramID:      vectorField(t, vectors.RingProgramID),
		InboxKey:           vectorField(t, vectors.InboxKey),
		InboxTags:          streamTags(t, vectors.InboxTags),
		FirstContactSecret: vectorField(t, vectors.FirstContactSecret),
		PairKey:            vectorField(t, vectors.PairKey),
		PairTags:           streamTags(t, vectors.PairTags),
	}
	copy(witness.RingProgramAddress[:], vectorBytes(t, vectors.RingProgramAddress, 32))
	copy(witness.ViewingPk[:], vectorBytes(t, vectors.ViewingPk, 33))
	for _, low := range vectors.Low248 {
		witness.Low248 = append(witness.Low248, low248Wires{Value: vectorField(t, low.Value), Tag: vectorField(t, low.Tag)})
	}
	circuit := &ringTagsCircuit{
		InboxTags: make([]streamTagWires, len(witness.InboxTags)),
		PairTags:  make([]streamTagWires, len(witness.PairTags)),
		Low248:    make([]low248Wires, len(witness.Low248)),
	}
	if err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("ring tag vector rejected, %v", err)
	}
	witness.PairTags[0].Index = vectors.PairTags[0].Index + 1
	if err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("pair tag accepted under another stream index")
	}
}

type ringSecretVectors struct {
	TxViewingSk        string `json:"tx_viewing_secret"`
	TxViewingPk        string `json:"tx_viewing_pk"`
	RecipientViewingPk string `json:"recipient_viewing_pk"`
	Agreement          string `json:"agreement"`
	Salt               string `json:"salt"`
	FirstNullifier     string `json:"first_nullifier"`
	BlindingSeed       string `json:"blinding_seed"`
	OutputBlindingSeed string `json:"output_blinding_seed"`
	Outputs            []struct {
		OutputIndex            int    `json:"output_index"`
		PackedSlotSecret       string `json:"packed_slot_secret"`
		PackedRingSecret       string `json:"packed_ring_secret"`
		PackedBlinding         string `json:"packed_blinding"`
		DeliveredSlotSecret    string `json:"delivered_slot_secret"`
		ConfidentialRingSecret string `json:"confidential_ring_secret"`
		ConfidentialBlinding   string `json:"confidential_blinding"`
		Tag                    string `json:"tag"`
		AnonymousRingSecret    string `json:"anonymous_ring_secret"`
		AnonymousBlinding      string `json:"anonymous_blinding"`
		ExitBlinding           string `json:"exit_blinding"`
	} `json:"outputs"`
	SenderKey             string `json:"sender_key"`
	SenderPkHash          string `json:"sender_pk_hash"`
	PrivateTxBlinding     string `json:"private_tx_blinding"`
	SenderCommitment      string `json:"sender_commitment"`
	DepositBlindingSecret string `json:"deposit_blinding_secret"`
	DepositBlinding       string `json:"deposit_blinding"`
}

type ringSecretsCircuit struct {
	OutputIndexes         []int `gnark:"-"`
	TxViewingSk           [32]frontend.Variable
	TxViewingPk           [33]frontend.Variable
	RecipientViewingPk    [33]frontend.Variable
	Agreement             [32]frontend.Variable
	Salt                  [16]frontend.Variable
	FirstNullifier        frontend.Variable
	BlindingSeed          frontend.Variable
	OutputBlindingSeed    frontend.Variable
	Outputs               []ringSecretWires
	SenderKey             [32]frontend.Variable
	SenderPkHash          frontend.Variable
	PrivateTxBlinding     frontend.Variable
	SenderCommitment      frontend.Variable
	DepositBlindingSecret frontend.Variable
	DepositBlinding       frontend.Variable
}

type ringSecretWires struct {
	PackedSlotSecret, PackedRingSecret, PackedBlinding                frontend.Variable
	DeliveredSlotSecret, ConfidentialRingSecret, ConfidentialBlinding frontend.Variable
	Tag, AnonymousRingSecret, AnonymousBlinding, ExitBlinding         frontend.Variable
}

func (c *ringSecretsCircuit) Define(api frontend.API) error {
	packedTxViewingSk := [2]frontend.Variable(gadget.PackBytesBE(api, c.TxViewingSk[:]))
	agreement := [2]frontend.Variable(gadget.PackBytesBE(api, c.Agreement[:]))
	txPk := [2]frontend.Variable(gadget.PackBytesBE(api, c.TxViewingPk[:]))
	recipient := [2]frontend.Variable(gadget.PackBytesBE(api, c.RecipientViewingPk[:]))
	salt := gadget.PackBytesBE(api, c.Salt[:])[0]
	outputSeed := shared.DeriveOutputBlindingSeed(api, c.FirstNullifier, c.BlindingSeed)
	api.AssertIsEqual(outputSeed, c.OutputBlindingSeed)
	for k, out := range c.Outputs {
		i := c.OutputIndexes[k]
		packed := base.PackedSlot{TxViewingSk: packedTxViewingSk, Salt: salt, OutputIndex: i, FirstNullifier: c.FirstNullifier}.Secret(api)
		api.AssertIsEqual(packed, out.PackedSlotSecret)
		packedRing := base.ConfidentialRingSecret(api, packed)
		api.AssertIsEqual(packedRing, out.PackedRingSecret)
		api.AssertIsEqual(shared.DeriveRingOutputBlinding(api, c.FirstNullifier, packedRing, i), out.PackedBlinding)
		delivered := base.DeliveredSlot{
			Agreement: agreement, TxPk: txPk, Recipient: recipient, Salt: salt, OutputIndex: i, FirstNullifier: c.FirstNullifier,
		}.Secret(api)
		api.AssertIsEqual(delivered, out.DeliveredSlotSecret)
		confidential := base.ConfidentialRingSecret(api, delivered)
		api.AssertIsEqual(confidential, out.ConfidentialRingSecret)
		api.AssertIsEqual(shared.DeriveRingOutputBlinding(api, c.FirstNullifier, confidential, i), out.ConfidentialBlinding)
		anonymous := base.AnonymousRingSecret(api, delivered, out.Tag)
		api.AssertIsEqual(anonymous, out.AnonymousRingSecret)
		api.AssertIsEqual(shared.DeriveRingOutputBlinding(api, c.FirstNullifier, anonymous, i), out.AnonymousBlinding)
		api.AssertIsEqual(shared.DeriveOutputBlinding(api, c.FirstNullifier, outputSeed, i), out.ExitBlinding)
	}
	senderPkHash := gadget.SolanaOwnerIdentity(api, c.SenderKey)
	api.AssertIsEqual(senderPkHash, c.SenderPkHash)
	privateTxBlinding := shared.DerivePrivateTxBlinding(api, c.FirstNullifier, c.BlindingSeed)
	api.AssertIsEqual(privateTxBlinding, c.PrivateTxBlinding)
	api.AssertIsEqual(base.SenderCommitment(api, senderPkHash, privateTxBlinding), c.SenderCommitment)
	api.AssertIsEqual(base.DepositBlinding(api, c.DepositBlindingSecret), c.DepositBlinding)
	return nil
}

func TestRingSecretsMatchRustVectors(t *testing.T) {
	var vectors ringSecretVectors
	readRingVector(t, "ring-secrets.json", &vectors)
	witness := &ringSecretsCircuit{
		FirstNullifier:        vectorField(t, vectors.FirstNullifier),
		BlindingSeed:          vectorField(t, vectors.BlindingSeed),
		OutputBlindingSeed:    vectorField(t, vectors.OutputBlindingSeed),
		SenderPkHash:          vectorField(t, vectors.SenderPkHash),
		PrivateTxBlinding:     vectorField(t, vectors.PrivateTxBlinding),
		SenderCommitment:      vectorField(t, vectors.SenderCommitment),
		DepositBlindingSecret: vectorField(t, vectors.DepositBlindingSecret),
		DepositBlinding:       vectorField(t, vectors.DepositBlinding),
	}
	copy(witness.TxViewingSk[:], vectorBytes(t, vectors.TxViewingSk, 32))
	copy(witness.TxViewingPk[:], vectorBytes(t, vectors.TxViewingPk, 33))
	copy(witness.RecipientViewingPk[:], vectorBytes(t, vectors.RecipientViewingPk, 33))
	copy(witness.Agreement[:], vectorBytes(t, vectors.Agreement, 32))
	copy(witness.Salt[:], vectorBytes(t, vectors.Salt, 16))
	copy(witness.SenderKey[:], vectorBytes(t, vectors.SenderKey, 32))
	for _, out := range vectors.Outputs {
		witness.OutputIndexes = append(witness.OutputIndexes, out.OutputIndex)
		witness.Outputs = append(witness.Outputs, ringSecretWires{
			PackedSlotSecret:       vectorField(t, out.PackedSlotSecret),
			PackedRingSecret:       vectorField(t, out.PackedRingSecret),
			PackedBlinding:         vectorField(t, out.PackedBlinding),
			DeliveredSlotSecret:    vectorField(t, out.DeliveredSlotSecret),
			ConfidentialRingSecret: vectorField(t, out.ConfidentialRingSecret),
			ConfidentialBlinding:   vectorField(t, out.ConfidentialBlinding),
			Tag:                    vectorField(t, out.Tag),
			AnonymousRingSecret:    vectorField(t, out.AnonymousRingSecret),
			AnonymousBlinding:      vectorField(t, out.AnonymousBlinding),
			ExitBlinding:           vectorField(t, out.ExitBlinding),
		})
	}
	circuit := &ringSecretsCircuit{OutputIndexes: witness.OutputIndexes, Outputs: make([]ringSecretWires, len(witness.Outputs))}
	if err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("ring secret vector rejected, %v", err)
	}
	witness.Outputs[0].Tag = new(big.Int).Add(vectorField(t, vectors.Outputs[0].Tag), big.NewInt(1))
	if err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("anonymous ring secret accepted under another tag")
	}
}

func readRingVector(t *testing.T, name string, into any) {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate domain_test.go")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../../test-vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("%s, %v", name, err)
	}
}

func streamTags(t *testing.T, vectors []streamTagVector) []streamTagWires {
	t.Helper()
	wires := make([]streamTagWires, len(vectors))
	for i, tag := range vectors {
		wires[i] = streamTagWires{Epoch: tag.Epoch, Index: tag.Index, Tag: vectorField(t, tag.Tag)}
	}
	return wires
}

func vectorField(t *testing.T, value string) *big.Int {
	t.Helper()
	field, ok := new(big.Int).SetString(value, 16)
	if !ok {
		t.Fatalf("invalid vector field %q", value)
	}
	return field
}

func vectorBytes(t *testing.T, value string, n int) []frontend.Variable {
	t.Helper()
	wires := make([]frontend.Variable, n)
	for i, b := range hexBytes(t, value, n) {
		wires[i] = int(b)
	}
	return wires
}
