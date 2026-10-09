package extractor

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/prover/circuits/formal/ve"
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

func TestEmcurveChecksCoverEveryKind(t *testing.T) {
	checks, err := CollectEmcurveChecks()
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[emfield.CheckKind]int{}
	for _, r := range checks.Records {
		kinds[r.Kind]++
	}
	for _, k := range []emfield.CheckKind{emfield.KindEval, emfield.KindAssertZero, emfield.KindLazy, emfield.KindCanonicalLimbwise, emfield.KindCanonicalGap} {
		if kinds[k] == 0 {
			t.Errorf("no %s record", k)
		}
	}
	if checks.Basis.FoldRows == nil || len(checks.Basis.InverseVandermonde) == 0 {
		t.Fatal("basis is missing fold rows or inverse Vandermonde matrices")
	}
	again, err := CollectEmcurveChecks()
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Records) != len(checks.Records) || RenderEmcurveChecks(again) != RenderEmcurveChecks(checks) {
		t.Fatal("deduplicated records are not stable across runs")
	}
	t.Logf("%d recorder calls, %d records, kinds %v, vinv degrees %v", checks.Calls, len(checks.Records), kinds, checks.Basis.Degrees())
	if dir := os.Getenv("EMCURVE_CHECKS_OUT"); dir != "" {
		write(t, filepath.Join(dir, "EmcurveChecks.lean"), RenderEmcurveChecks(checks))
		write(t, filepath.Join(dir, "Field", "Certificate.lean"), RenderEmcurveCertificate(checks))
	}
}

func TestEmcurveRecorderAddsNoConstraints(t *testing.T) {
	digest := func() [32]byte {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &ve.AgreeKey{})
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if _, err := cs.WriteTo(&buf); err != nil {
			t.Fatal(err)
		}
		return sha256.Sum256(buf.Bytes())
	}
	plain := digest()
	emfield.Recorder = func(emfield.CheckRecord) {}
	emfield.RecordBasis = func(emfield.BasisRecord) {}
	recorded := digest()
	emfield.Recorder, emfield.RecordBasis = nil, nil
	if plain != recorded {
		t.Fatal("installing the recorder changed the constraint system")
	}
}

var extractedCheckName = regexp.MustCompile(`(?m)^def (CheckPolynomial|Lazy)_[0-9]+_h([0-9a-f]{8}) `)

func TestEmcurveChecksMatchExtractedGadgets(t *testing.T) {
	checks, err := CollectEmcurveChecks()
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[string]bool{}
	for _, r := range checks.Records {
		switch r.Kind {
		case emfield.KindEval, emfield.KindAssertZero, emfield.KindLazy:
			recorded[recordName(r)] = true
		}
	}
	modules, err := extractVE()
	if err != nil {
		t.Fatal(err)
	}
	extracted := map[string]bool{}
	for _, source := range modules {
		for _, m := range extractedCheckName.FindAllStringSubmatch(source, -1) {
			prefix := "cert_h"
			if m[1] == "Lazy" {
				prefix = "lazy_h"
			}
			extracted[prefix+m[2]] = true
		}
	}
	for name := range extracted {
		if !recorded[name] {
			t.Errorf("extracted gadget %s has no certificate record", name)
		}
	}
	for name := range recorded {
		if !extracted[name] {
			t.Errorf("certificate record %s has no extracted gadget", name)
		}
	}
	t.Logf("%d extracted check gadgets, %d records", len(extracted), len(recorded))
}

func TestEmcurveInstancesRender(t *testing.T) {
	checks, err := CollectEmcurveChecks()
	if err != nil {
		t.Fatal(err)
	}
	modules, err := extractVE()
	if err != nil {
		t.Fatal(err)
	}
	files, err := RenderEmcurveInstances(checks, modules)
	if err != nil {
		t.Fatal(err)
	}
	theorems := 0
	for _, src := range files {
		theorems += strings.Count(src, "_sound (")
	}
	if theorems != 161 {
		t.Fatalf("%d instance soundness theorems, want 161", theorems)
	}
	if dir := os.Getenv("EMCURVE_CHECKS_OUT"); dir != "" {
		for module, src := range files {
			write(t, filepath.Join(dir, "Field", strings.TrimPrefix(module, "VerifiableEncryption.Field.")+".lean"), src)
		}
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if !strings.HasSuffix(content, "\n") {
		t.Fatalf("%s: missing trailing newline", path)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
