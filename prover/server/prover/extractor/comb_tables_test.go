package extractor

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/secp256r1"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve"
)

const combTablesPath = "../../formal-verification/VerifiableEncryption/CombTables.lean"

func multipleOfGenerator(t *testing.T, scalar *big.Int) [2]*big.Int {
	t.Helper()
	reduced := new(big.Int).Mod(scalar, emcurve.GroupOrder())
	if reduced.Sign() == 0 {
		t.Fatalf("scalar %v is a multiple of the group order", scalar)
	}
	_, generator := secp256r1.Generators()
	var product secp256r1.G1Affine
	product.ScalarMultiplication(&generator, reduced)
	return [2]*big.Int{product.X.BigInt(new(big.Int)), product.Y.BigInt(new(big.Int))}
}

func TestCombTablesMatchGeneratorMultiples(t *testing.T) {
	windows, topEven := emcurve.CombTables()
	const windowBits, topWindowBits = 7, 4
	if len(windows) != 37 {
		t.Fatalf("window count %d, want 37", len(windows))
	}
	for w, window := range windows {
		width := windowBits
		if w == len(windows)-1 {
			width = topWindowBits
		}
		if len(window) != 1<<width {
			t.Fatalf("window %d has %d entries, want %d", w, len(window), 1<<width)
		}
		for j, entry := range window {
			digit := big.NewInt(int64(2*j + 1 - (1 << width)))
			want := multipleOfGenerator(t, new(big.Int).Lsh(digit, uint(windowBits*w)))
			if entry[0].Cmp(want[0]) != 0 || entry[1].Cmp(want[1]) != 0 {
				t.Fatalf("window %d entry %d is not %v * 2^%d * G", w, j, digit, windowBits*w)
			}
		}
	}
	if len(topEven) != 1<<topWindowBits {
		t.Fatalf("top-even count %d, want %d", len(topEven), 1<<topWindowBits)
	}
	topShift := uint(windowBits * (len(windows) - 1))
	for j, entry := range topEven {
		digit := big.NewInt(int64(2*j + 1 - (1 << topWindowBits)))
		want := multipleOfGenerator(t, new(big.Int).Sub(new(big.Int).Lsh(digit, topShift), big.NewInt(1)))
		if entry[0].Cmp(want[0]) != 0 || entry[1].Cmp(want[1]) != 0 {
			t.Fatalf("top-even entry %d is not %v * 2^%d * G - G", j, digit, topShift)
		}
	}
}

// TestCombTablesLeanUpToDate pins the committed Lean data to the Go tables.
// Regenerate with UPDATE_COMB_TABLES=1.
func TestCombTablesLeanUpToDate(t *testing.T) {
	rendered := ExtractCombTables()
	path := filepath.FromSlash(combTablesPath)
	if os.Getenv("UPDATE_COMB_TABLES") != "" {
		if err := os.WriteFile(path, []byte(rendered), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(committed) != rendered {
		t.Fatal("CombTables.lean is stale; rerun with UPDATE_COMB_TABLES=1")
	}
}
