package extractor

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var hintComment = regexp.MustCompile(`-- hint (\S+)`)

// Every hint left in the extracted circuits must be one whose outputs the
// circuit constrains explicitly. A hint outside this list usually means a
// lookup or commitment-based argument lost its extraction seam.
var allowedVEHints = map[string]bool{
	"github.com/consensys/gnark/std/math/bits.nBits":                                        true,
	"zolana/prover/circuits/verifiable-encryption/aes.laneChunksHint":                       true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield.BalanceHint":         true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield.PlainCheckHint":      true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield.decomposeHint":       true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield.modulusGapHint":      true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256AddHint":                 true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256CombChainHint":           true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256CombRecodeHint":          true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256DecomposeScalarHint":     true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256HalfTangentHint":         true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256ImplicitChordHint":       true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256ImplicitSecondSlopeHint": true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256LimbBytesHint":           true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256RatioHint":               true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256ScalarMulHint":           true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256SplitLowBitsHint":        true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256TangentHint":             true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256UnifiedSlopeHint":        true,
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve.p256XEqualHint":              true,
}

func TestExtractVELean(t *testing.T) {
	modules, err := extractVE()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := modules[veModuleLayout.Root]; !ok {
		t.Fatal("missing the root module")
	}
	seen := map[string]bool{}
	for name, source := range modules {
		if strings.Contains(source, "panic") {
			t.Errorf("module %s mentions panic", name)
		}
		for _, m := range hintComment.FindAllStringSubmatch(source, -1) {
			seen[m[1]] = true
		}
	}
	for name := range seen {
		if !allowedVEHints[name] {
			t.Errorf("hint %s is not in the allowlist", name)
		}
	}
}

func readTree(root string) (map[string]string, error) {
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		files[path] = string(data)
		return err
	})
	return files, err
}

func TestWriteVELean(t *testing.T) {
	dir := t.TempDir()
	if _, err := ExtractVELean(dir); err != nil {
		t.Fatal(err)
	}
	first, err := readTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractVELean(dir); err != nil {
		t.Fatal(err)
	}
	second, err := readTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("re-extraction wrote %d files, first %d", len(second), len(first))
	}
	for path, source := range first {
		if second[path] != source {
			t.Errorf("re-extraction changed %s", path)
		}
	}
}
