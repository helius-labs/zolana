package ve

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	mergeshared "zolana/prover/circuits/spp_merge/shared"
)

func exprString(t *testing.T, fset *token.FileSet, e ast.Expr) string {
	t.Helper()
	var sb strings.Builder
	if err := printer.Fprint(&sb, fset, e); err != nil {
		t.Fatal(err)
	}
	return sb.String()
}

// TestEnvelopeMergeMatchesMergeRail pins EnvelopeMerge to the envelope of
// spp_merge/default.go: the same ve.Envelope fields from the same merge
// constants, Context set to the first nullifier, and the public elements and
// blinding derived from the result.
func TestEnvelopeMergeMatchesMergeRail(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("..", "..", "spp_merge", "default.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var envelopes []*ast.CompositeLit
	calls := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			if exprString(t, fset, x.Type) == "ve.Envelope" {
				envelopes = append(envelopes, x)
			}
		case *ast.CallExpr:
			calls[exprString(t, fset, x.Fun)] = true
		}
		return true
	})
	if len(envelopes) != 1 {
		t.Fatalf("default.go builds %d envelopes, want 1", len(envelopes))
	}
	fields := map[string]string{}
	for _, elt := range envelopes[0].Elts {
		kv := elt.(*ast.KeyValueExpr)
		fields[exprString(t, fset, kv.Key)] = exprString(t, fset, kv.Value)
	}
	want := map[string]string{
		"SecretTag":   "mergeshared.MergeSecretTag",
		"KdfInfo":     "mergeshared.MergeKdfInfo",
		"EphemeralSk": "c.EphemeralSk",
		"RecipientPk": "c.ViewingPk",
		"Plaintext":   "mergeshared.MergePlaintext(api, amountBytes, c.MintChunks)",
		"Context":     "c.Nullifiers[0]",
	}
	for k, v := range want {
		if fields[k] != v {
			t.Errorf("default.go envelope field %s = %q, want %q", k, fields[k], v)
		}
	}
	if len(fields) != len(want) {
		t.Errorf("default.go envelope sets %v, want exactly %v", fields, want)
	}
	for _, call := range []string{"mergeshared.EnvelopePublicElements", "mergeshared.MergeDerivedBlinding"} {
		if !calls[call] {
			t.Errorf("default.go no longer calls %s", call)
		}
	}
}

type mergePlaintextLength struct {
	Amount     [mergeshared.MergeAmountBytes]frontend.Variable
	MintChunks [mergeshared.MintChunkCount]frontend.Variable
	length     *int
}

func (c *mergePlaintextLength) Define(api frontend.API) error {
	*c.length = len(mergeshared.MergePlaintext(api, c.Amount[:], c.MintChunks))
	return nil
}

// TestMergePlaintextLength checks that merge encrypts exactly as many bytes as
// EnvelopeMerge takes.
func TestMergePlaintextLength(t *testing.T) {
	length := 0
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &mergePlaintextLength{length: &length}); err != nil {
		t.Fatal(err)
	}
	if length != len(EnvelopeMerge{}.Plaintext) {
		t.Fatalf("merge plaintext has %d bytes, EnvelopeMerge takes %d", length, len(EnvelopeMerge{}.Plaintext))
	}
}
