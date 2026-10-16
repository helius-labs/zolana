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
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Rust and TypeScript pin the same file, WRITE_AUDIT_VECTORS=1 rewrites it from the host mirror.
const disclosureVectorPath = "../../../../../test-vectors/audit-disclosure.json"

const disclosureVectorDescription = "Known-answer vector for the ring audit output disclosure. " +
	"key is the 32 transaction viewing secret bytes, key_lo and key_hi are PackBytesBE(key) (the first 31 bytes, then the last byte), " +
	"salt_field is the 16 salt bytes right-aligned. s = Poseidon(0x4352_5f4f44, key_lo, key_hi, salt_field), then for i in 0..36 " +
	"s = Poseidon(s, i) and pad[i] = s. ciphertext[i] = (fields[i] + pad[i]) mod r and disclosure_hash = hash_chain_4(ciphertext). " +
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

// The key is below the P-256 order and RFC 7748 clamped, so either viewing key curve accepts it.
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
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	path := filepath.Join(filepath.Dir(source), disclosureVectorPath)
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
	var got disclosureVector
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("the host mirror disagrees with test-vectors/audit-disclosure.json, rewrite it with WRITE_AUDIT_VECTORS=1")
	}

	// The circuit solves only when its disclosure hash is the pinned one.
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
	elements := keys.ChainElementsFor(t, statement)
	pinned, err := hex.DecodeString(got.DisclosureHash)
	if err != nil {
		t.Fatal(err)
	}
	elements[len(elements)-1] = new(big.Int).SetBytes(pinned)
	solve(t, testConstraintSystem(t), &base.CustomRingBaseCircuit{
		PublicInputHash: spptest.MustHashChain(t, elements),
		Audit:           statement.Audit,
		NOut:            statement.Count,
		Outputs:         statement.Outputs,
	})
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
