package extractor

import (
	"math/big"
	"os"
	"strings"
	"testing"

	"zolana/prover/circuits/verifiable-encryption/aes"
)

func TestAesTableShapes(t *testing.T) {
	substitution := aes.SubstitutionTable()
	if len(substitution) != 1280 {
		t.Fatalf("substitution has %d entries, want 1280", len(substitution))
	}
	spreadBytes := aes.SpreadByteTable()
	if len(spreadBytes) != 256 {
		t.Fatalf("spread bytes has %d entries, want 256", len(spreadBytes))
	}
	parity := aes.ChunkParityTable()
	if len(parity) != 1296 {
		t.Fatalf("chunk parity has %d entries, want 1296", len(parity))
	}
	sixToSeven := new(big.Int).Exp(big.NewInt(6), big.NewInt(7), nil)
	if spreadBytes[0x80].Cmp(sixToSeven) != 0 {
		t.Fatalf("spread of 0x80 is %s, want 6^7", spreadBytes[0x80])
	}
	if parity[1] != 1 {
		t.Fatalf("chunk parity of 1 is %d, want 1", parity[1])
	}
	if parity[1295] != 15 {
		t.Fatalf("chunk parity of 1295 is %d, want 15", parity[1295])
	}
	sbox := aes.SboxTable()
	spreadSbox0 := substitution[4*256]
	if want := spreadBytes[sbox[0]]; spreadSbox0.Cmp(want) != 0 {
		t.Fatalf("sbox region entry 0 is %s, want %s", spreadSbox0, want)
	}
}

func TestAesTablesLeanIsCurrent(t *testing.T) {
	generated := ExtractAesTables()
	if !strings.HasPrefix(generated, "-- Code generated") {
		t.Fatal("generated module lacks the generated-code header")
	}
	const committedPath = "../../formal-verification/VerifiableEncryption/AesTables.lean"
	if os.Getenv("UPDATE_AES_TABLES") == "1" {
		if err := os.WriteFile(committedPath, []byte(generated), 0o644); err != nil {
			t.Fatalf("write AesTables.lean: %v", err)
		}
	}
	committed, err := os.ReadFile(committedPath)
	if err != nil {
		t.Fatalf("read committed AesTables.lean: %v", err)
	}
	if string(committed) != generated {
		t.Fatal("formal-verification/VerifiableEncryption/AesTables.lean is stale; regenerate it from ExtractAesTables")
	}
}
