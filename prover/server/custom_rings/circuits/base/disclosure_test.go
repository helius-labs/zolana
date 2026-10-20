package base_test

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	base "github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Rust and TypeScript pin the same file, WRITE_AUDIT_VECTORS=1 rewrites it from the host mirror.
const disclosureVectorPath = "../../../../../test-vectors/audit-disclosure.json"

const disclosureVectorDescription = "Known-answer vector for the ring audit output disclosure. " +
	"key is the 32 transaction viewing secret bytes, key_lo and key_hi are PackBytesBE(key) (the first 31 bytes, then the last byte), " +
	"salt_field is the 16 salt bytes right-aligned. seed = Poseidon(0x4352_5f4f44, key_lo, key_hi, salt_field), then for i in 0..36 " +
	"pad[i] = Poseidon(seed, i). ciphertext[i] = (fields[i] + pad[i]) mod r and disclosure_hash = hash_chain_4(ciphertext). " +
	"fields[i] = i, the last field is r - 1 so its sum wraps. All values are 32-byte big-endian hex. " +
	"Produced by prover/server/custom_rings/circuits/base/disclosure_test.go with WRITE_AUDIT_VECTORS=1."

type disclosureVector struct {
	Description    string   `json:"description"`
	Key            string   `json:"key"`
	Salt           string   `json:"salt"`
	Fields         []string `json:"fields"`
	Pad            []string `json:"pad"`
	Ciphertext     []string `json:"ciphertext"`
	DisclosureHash string   `json:"disclosure_hash"`
}

// The pinned viewing key is clamped as required by RFC 7748.
func vectorKey() (key [32]byte, salt [16]byte) {
	for i := range key {
		key[i] = 0x10 + byte(i)
	}
	key[31] = 0x4f
	for i := range salt {
		salt[i] = 0xa0 + byte(i)
	}
	return key, salt
}

func vectorFields() []*big.Int {
	fields := make([]*big.Int, base.AuditOutputSlots*base.AuditOutputFieldCount)
	for i := range fields {
		fields[i] = big.NewInt(int64(i))
	}
	fields[len(fields)-1] = new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
	return fields
}

func TestDisclosureVectorPinsHostAndCircuit(t *testing.T) {
	key, salt := vectorKey()
	fields := vectorFields()
	ciphertext, hash := ringaudit.Disclose(t, key, salt, fields)
	want := disclosureVector{
		Description:    disclosureVectorDescription,
		Key:            hex.EncodeToString(key[:]),
		Salt:           hex.EncodeToString(salt[:]),
		Fields:         hexFields(t, fields),
		Pad:            hexFields(t, ringaudit.DisclosurePad(t, key, salt, len(fields))),
		Ciphertext:     hexFields(t, ciphertext),
		DisclosureHash: hexFields(t, []*big.Int{hash})[0],
	}
	var got disclosureVector
	readVector(t, disclosureVectorPath, want, &got)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("the host mirror disagrees with test-vectors/audit-disclosure.json, rewrite it with WRITE_AUDIT_VECTORS=1")
	}

	keys := ringaudit.DefaultKeys(t).WithTxScalar(t, key)
	statement := keys.Statement(big.NewInt(0xabcdef))
	statement.Count = base.AuditOutputSlots
	for i, b := range salt {
		statement.Audit.Salt[i] = int(b)
	}
	for i := range statement.Outputs {
		f := fields[i*base.AuditOutputFieldCount:]
		statement.Outputs[i] = base.AuditOutputWires{
			Domain: f[0], TreeID: f[1], OwnerHash: f[2], Asset: f[3], Amount: f[4],
			Blinding: f[5], DataHash: f[6], RingDataHash: f[7], RingProgramID: f[8],
		}
	}
	solvePinned(t, keys, statement, got.DisclosureHash)
}

// A fully known chunk unmasks its own pad and nothing else, the seed stays secret.
func TestDisclosurePadIndexesAreIndependent(t *testing.T) {
	key, salt := vectorKey()
	pad := ringaudit.DisclosurePad(t, key, salt, base.AuditOutputSlots*base.AuditOutputFieldCount)
	var pinned disclosureVector
	readVector(t, disclosureVectorPath, nil, &pinned)
	if !reflect.DeepEqual(hexFields(t, pad), pinned.Pad) {
		t.Fatal("the pad differs from test-vectors/audit-disclosure.json")
	}
	for i := 0; i+1 < len(pad); i++ {
		chained := spptest.MustPoseidon(t, 3, []*big.Int{pad[i], big.NewInt(int64(i + 1))})
		if chained.Cmp(pad[i+1]) == 0 {
			t.Fatalf("pad[%d] derives pad[%d]", i, i+1)
		}
	}
}

// solvePinned solves the circuit only when its disclosure hash is the pinned one.
func solvePinned(t *testing.T, keys ringaudit.Keys, statement ringaudit.Statement, pinnedHex string) {
	t.Helper()
	elements := keys.BaseChainElementsFor(t, statement)
	pinned, err := hex.DecodeString(pinnedHex)
	if err != nil {
		t.Fatal(err)
	}
	elements[chainDisclosureHash] = new(big.Int).SetBytes(pinned)
	circuit := keys.Circuit(t, statement)
	circuit.PublicInputHash = spptest.MustHashChain(t, elements)
	solve(t, testConstraintSystem(t), circuit)
}

const chainDisclosureHash = 11

const anonymousVectorPath = "../../../../../test-vectors/audit-disclosure-anonymous.json"

const anonymousVectorDescription = "Known-answer vector for the anonymous ring audit disclosure. " +
	"key and salt are the ones of audit-disclosure.json and the pad shares its seed, so it is a prefix of that vector's pad. " +
	"plaintext is the published slots, the sender identity padded to 62 bytes, then n_in input slots of 93 bytes " +
	"(tree id u16, amount u64, asset, blinding) and n_out output slots of 124 bytes (recipient identity, nullifier pk, " +
	"recipient viewing pk), all big-endian and a dummy slot all zero. " +
	"fields[j] is plaintext[31j..31j+31] read big-endian, ciphertext[j] = (fields[j] + pad[j]) mod r and " +
	"disclosure_hash = hash_chain_4(ciphertext) over the 2 + 3 n_in + 4 n_out published fields. " +
	"Produced by prover/server/custom_rings/circuits/base/disclosure_test.go with WRITE_AUDIT_VECTORS=1."

type anonymousVector struct {
	Description    string   `json:"description"`
	Key            string   `json:"key"`
	Salt           string   `json:"salt"`
	NIn            int      `json:"n_in"`
	NOut           int      `json:"n_out"`
	Plaintext      string   `json:"plaintext"`
	Fields         []string `json:"fields"`
	Pad            []string `json:"pad"`
	Ciphertext     []string `json:"ciphertext"`
	DisclosureHash string   `json:"disclosure_hash"`
}

// The anonymous vector publishes past the 36 legacy fields, with dummy slots, a ring note and a note leaving the ring.
func anonymousVectorStatement(t *testing.T) (ringaudit.Keys, ringaudit.Statement) {
	key, salt := vectorKey()
	keys := ringaudit.DefaultKeys(t).WithTxScalar(t, key)
	statement := keys.AnonymousStatement(t)
	for i, b := range salt {
		statement.Audit.Salt[i] = int(b)
	}
	spent := statement.Inputs[0]
	spent.Amount, spent.Blinding, spent.TreeID = big.NewInt(250), big.NewInt(52), big.NewInt(4)
	statement.Inputs[1].Domain = big.NewInt(protocol.DummyDomain)
	statement.Inputs[2], statement.NIn = spent, 3

	ring := statement.Notes[0]
	ring.Amount = big.NewInt(150)
	statement.Notes[1].Domain = big.NewInt(protocol.DummyDomain)
	leaving := ring
	leaving.Amount, leaving.Blinding, leaving.RingProgramID, leaving.RingDataHash = big.NewInt(100), big.NewInt(62), big.NewInt(0), big.NewInt(0)
	other := append([]byte{0x50}, make32(0xd4)...)
	hash, err := protocol.HashBytes(other)
	if err != nil {
		t.Fatal(err)
	}
	leaving.OwnerPkHash = hash
	statement.Notes[2], statement.Notes[3] = leaving, ring
	for i, b := range other {
		statement.Audit.Recipients[2][i] = int(b)
	}
	statement.Audit.Recipients[3] = statement.Audit.Recipients[0]
	statement.Audit.RecipientViewingKeys[2] = statement.Audit.RecipientViewingKeys[0]
	statement.Audit.RecipientViewingKeys[3] = statement.Audit.RecipientViewingKeys[0]
	statement.Deliveries[3] = statement.Deliveries[0]
	statement.Count = base.AuditOutputSlots
	keys.Deliver(t, &statement)
	return keys, statement
}

func TestAnonymousDisclosureVectorPinsHostAndCircuit(t *testing.T) {
	key, salt := vectorKey()
	keys, statement := anonymousVectorStatement(t)
	plaintext := ringaudit.AnonymousPlaintext(statement)
	fields := ringaudit.PackChunks(plaintext)
	ciphertext, hash := ringaudit.Disclose(t, key, salt, fields)
	want := anonymousVector{
		Description:    anonymousVectorDescription,
		Key:            hex.EncodeToString(key[:]),
		Salt:           hex.EncodeToString(salt[:]),
		NIn:            statement.NIn,
		NOut:           statement.Count,
		Plaintext:      hex.EncodeToString(plaintext),
		Fields:         hexFields(t, fields),
		Pad:            hexFields(t, ringaudit.DisclosurePad(t, key, salt, len(fields))),
		Ciphertext:     hexFields(t, ciphertext),
		DisclosureHash: hexFields(t, []*big.Int{hash})[0],
	}
	if len(fields) != 2+3*statement.NIn+4*statement.Count {
		t.Fatalf("%d published fields", len(fields))
	}
	var got anonymousVector
	readVector(t, anonymousVectorPath, want, &got)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("the host mirror disagrees with test-vectors/audit-disclosure-anonymous.json, rewrite it with WRITE_AUDIT_VECTORS=1")
	}
	var legacy disclosureVector
	readVector(t, disclosureVectorPath, nil, &legacy)
	if len(got.Pad) > len(legacy.Pad) || !reflect.DeepEqual(legacy.Pad[:len(got.Pad)], got.Pad) {
		t.Fatal("the anonymous pad is not a prefix of the legacy pad")
	}
	solvePinned(t, keys, statement, got.DisclosureHash)
}

// readVector rewrites the file from want under WRITE_AUDIT_VECTORS=1, a nil want only reads.
func readVector(t *testing.T, relative string, want, got any) {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	path := filepath.Join(filepath.Dir(source), relative)
	if want != nil && os.Getenv("WRITE_AUDIT_VECTORS") != "" {
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
	if err := json.Unmarshal(raw, got); err != nil {
		t.Fatal(err)
	}
}

func hexFields(t *testing.T, values []*big.Int) []string {
	t.Helper()
	out := make([]string, len(values))
	for i, value := range values {
		bytes := spptest.MustFieldBytes(t, value)
		out[i] = hex.EncodeToString(bytes[:])
	}
	return out
}
