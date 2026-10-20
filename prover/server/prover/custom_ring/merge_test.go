package custom_ring

import (
	"encoding/json"
	"math/big"
	"os"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/merge"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringmerge"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func TestMergeAnonymousCatalogFollowsTheSppWidths(t *testing.T) {
	if !slices.Equal(common.MergeAnonymousWidths, mergeshared.SupportedInputCounts) {
		t.Fatalf("anonymous merge widths %v, SPP merges %v", common.MergeAnonymousWidths, mergeshared.SupportedInputCounts)
	}
	for _, width := range common.MergeAnonymousWidths {
		kind := common.CustomRingMergeAnonymousCircuitType(width)
		if _, err := Ring(kind); err != nil {
			t.Fatal(err)
		}
		if !kind.IsRing() || common.KeyFileCircuit(common.RingKeyFile(kind)) != kind {
			t.Fatalf("key catalog mismatch: %s", kind)
		}
	}
	if common.CircuitType("custom-ring-merge-anonymous-9").IsRing() {
		t.Fatal("a width without an SPP merge key is recognized")
	}
}

func mergeParams(t *testing.T, s *ringmerge.Statement) *MergeAnonymousParams {
	t.Helper()
	c := s.Circuit
	field := func(value frontend.Variable) Field { return Field{spptest.AsBigInt(value)} }
	bytes := func(values [32]frontend.Variable) Bytes {
		out := make(Bytes, len(values))
		for i, value := range values {
			out[i] = byte(spptest.AsBigInt(value).Uint64())
		}
		return out
	}
	p := &MergeAnonymousParams{
		CircuitType:        string(common.CustomRingMergeAnonymousCircuitType(len(c.Inputs))),
		PublicInputHash:    field(c.PublicInputHash),
		PrivateTxHash:      field(c.PrivateTxHash),
		OutputUtxoHash:     field(c.OutputUtxoHash),
		FirstNullifier:     field(c.FirstNullifier),
		RingProgramID:      field(c.RingProgramID),
		MemberRegistryRoot: field(c.MemberRegistryRoot),
		AuditorPk:          bytes(c.AuditorPk),
		Salt:               field(c.Salt),
		EphSk:              bytes(c.EphSk),
		DisclosureKey:      bytes(c.DisclosureKey),
		OwnerKey:           bytes(c.OwnerKey),
		NullifierSecret:    field(c.NullifierSecret),
		MintChunks:         []Field{field(c.MintChunks[0]), field(c.MintChunks[1])},
		OutputTreeID:       field(c.OutputTreeID),
		OutputRingDataHash: field(c.OutputRingDataHash),
		MemberRecord: RecordOpening{
			Next: field(c.MemberRecord.Next), Lists: spptest.AsBigInt(c.MemberRecord.Lists).Uint64(),
			EscrowKey: field(c.MemberRecord.EscrowKey), Index: spptest.AsBigInt(c.MemberRecord.Index).Uint64(),
		},
	}
	for _, element := range c.MemberRecord.Path {
		p.MemberRecord.Path = append(p.MemberRecord.Path, field(element))
	}
	for _, in := range c.Inputs {
		p.Inputs = append(p.Inputs, MergeInput{
			Domain: field(in.Domain), TreeID: field(in.TreeID), Amount: field(in.Amount),
			Blinding: field(in.Blinding), RingDataHash: field(in.RingDataHash),
		})
	}
	return p
}

func TestMergeAnonymousRequestDecodesAndSolves(t *testing.T) {
	kind := common.CustomRingMergeAnonymousCircuitType(8)
	cs := compileRing(t, kind)
	p := mergeParams(t, ringmerge.Build(t, 8))
	witness, err := frontend.NewWitness(decodeParams(t, kind, p), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Solve(witness); err != nil {
		t.Fatal(err)
	}
	p.Inputs = p.Inputs[:7]
	if _, err := Decode(kind, mustMarshal(t, p)); err == nil {
		t.Fatal("a request with a missing slot assigned")
	}
	p.Inputs = append(p.Inputs, p.Inputs[0], p.Inputs[0])
	if _, err := Decode(kind, mustMarshal(t, p)); err == nil {
		t.Fatal("a request with an extra slot assigned")
	}
	p.Inputs = p.Inputs[:8]
	p.OwnerKey = p.OwnerKey[:31]
	if _, err := Decode(kind, mustMarshal(t, p)); err == nil {
		t.Fatal("a short owner key assigned")
	}
	p.OwnerKey = append(p.OwnerKey, 0)
	p.MintChunks = p.MintChunks[:1]
	if _, err := Decode(kind, mustMarshal(t, p)); err == nil {
		t.Fatal("one mint chunk assigned")
	}
}

func mustMarshal(t *testing.T, params any) []byte {
	t.Helper()
	payload, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// Rust and TypeScript pin the same file, WRITE_AUDIT_VECTORS=1 rewrites it from the host mirror.
const mergeVectorPath = "../../../../test-vectors/ring-merge-anonymous.json"

const mergeVectorDescription = "Known-answer vector for the anonymous ring merge disclosure and statement, width 8. " +
	"plaintext = owner_key(32) || nullifier_pk(32) || mint(32) || amount u64 big-endian || output_blinding(32) || input_commitments(8 x 32), " +
	"zero padded to 31-byte chunks, chunk i a big-endian field. seed = Poseidon(0x4352_5f4d44, key_lo, key_hi, salt_field) with key_lo and key_hi " +
	"PackBytesBE(disclosure_key) and salt_field the 16 salt bytes right aligned, fields[i] = (chunk[i] + Poseidon(seed, i)) mod r. " +
	"envelope_ciphertext seals disclosure_key from eph to auditor under info CRING/mrg1 as the base Envelope does. " +
	"elements = CRMG, private_tx_hash, output_utxo_hash, first_nullifier, ring_program_id, member_registry_root, auditor lo, hi, eph lo, hi, " +
	"hash_bytes(envelope_ciphertext), salt_field, hash_chain_4(fields), public_input_hash = hash_chain(elements). " +
	"request is the prover body. Produced by prover/server/prover/custom_ring/merge_test.go with WRITE_AUDIT_VECTORS=1."

type mergeVector struct {
	Description        string                `json:"description"`
	Width              int                   `json:"width"`
	AuditorSk          Bytes                 `json:"auditor_sk"`
	AuditorPk          Bytes                 `json:"auditor_pk"`
	EphPk              Bytes                 `json:"eph_pk"`
	Salt               Bytes                 `json:"salt"`
	Mint               Bytes                 `json:"mint"`
	NullifierPk        Field                 `json:"nullifier_pk"`
	Amount             uint64                `json:"amount"`
	OutputBlinding     Field                 `json:"output_blinding"`
	InputCommitments   []Field               `json:"input_commitments"`
	Plaintext          Bytes                 `json:"plaintext"`
	Fields             []Field               `json:"fields"`
	EnvelopeCiphertext Bytes                 `json:"envelope_ciphertext"`
	Elements           []Field               `json:"elements"`
	PublicInputHash    Field                 `json:"public_input_hash"`
	Request            *MergeAnonymousParams `json:"request"`
}

func TestMergeAnonymousVectorPinsHostAndCircuit(t *testing.T) {
	s := ringmerge.Build(t, 8)
	auditorSk := ringaudit.Scalar(0x33)
	auditorU := s.Keys.AuditorPk()
	auditorPk := ringaudit.Tagged(auditorU[:])
	ephPk := s.Keys.EphPk()
	fields := func(values []*big.Int) []Field {
		out := make([]Field, len(values))
		for i, value := range values {
			out[i] = Field{value}
		}
		return out
	}
	request := mergeParams(t, s)
	want := mergeVector{
		Description:        mergeVectorDescription,
		Width:              8,
		AuditorSk:          auditorSk[:],
		AuditorPk:          auditorPk[:],
		EphPk:              ephPk[:],
		Salt:               s.Salt[:],
		Mint:               s.Mint[:],
		NullifierPk:        Field{s.NullifierPk},
		Amount:             new(big.Int).Add(s.Amounts[0], s.Amounts[1]).Uint64(),
		OutputBlinding:     Field{s.OutputBlinding},
		InputCommitments:   fields(s.InputHashes),
		Plaintext:          s.Plaintext,
		Fields:             fields(s.Fields),
		EnvelopeCiphertext: s.Keys.EnvelopeCiphertext(t, s.DisclosureKey[:], merge.EncryptionInfo),
		Elements:           fields(s.Elements(t)),
		PublicInputHash:    Field{spptest.AsBigInt(s.Circuit.PublicInputHash)},
		Request:            request,
	}
	path := mergeVectorPath
	if os.Getenv("WRITE_AUDIT_VECTORS") != "" {
		encoded, err := json.MarshalIndent(want, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(append(encoded, '\n')) {
		t.Fatal("the host mirror disagrees with test-vectors/ring-merge-anonymous.json, rewrite it with WRITE_AUDIT_VECTORS=1")
	}
	var pinned mergeVector
	if err := json.Unmarshal(raw, &pinned); err != nil {
		t.Fatal(err)
	}
	kind := common.CustomRingMergeAnonymousCircuitType(8)
	witness, err := frontend.NewWitness(decodeParams(t, kind, pinned.Request), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compileRing(t, kind).Solve(witness); err != nil {
		t.Fatal(err)
	}
}
