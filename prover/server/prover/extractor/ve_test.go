package extractor

import (
	"os"
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
	out, err := ExtractVELean()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "panic") {
		t.Error("extracted circuits mention panic")
	}
	seen := map[string]bool{}
	for _, m := range hintComment.FindAllStringSubmatch(out, -1) {
		seen[m[1]] = true
	}
	for name := range seen {
		if !allowedVEHints[name] {
			t.Errorf("hint %s is not in the allowlist", name)
		}
	}
	if path := os.Getenv("VE_LEAN_OUT"); path != "" {
		if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
