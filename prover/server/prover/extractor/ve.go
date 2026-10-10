package extractor

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	leanextractor "github.com/reilabs/gnark-lean-extractor/v3/extractor"

	"zolana/prover/circuits/formal/ve"
)

// Vector access without bound-proof tactics and bodies split into parts of at
// most 200 operations keep every definition shallow enough to elaborate; named
// big constants keep the output small.
var veExportOptions = leanextractor.ExportOptions{VectorGet: true, MaxBodyApps: 200, NamedConstantDigits: 20}

// The extraction is split into modules that elaborate separately, keeping the
// peak memory of each Lean process within a CI runner.
var veModuleLayout = leanextractor.ModuleLayout{
	Root:     "VerifiableEncryption.Circuit",
	Prelude:  "Prelude",
	Circuits: "Top",
	Rules: []leanextractor.ModuleRule{
		{Module: "Field", Prefixes: []string{"CheckPolynomial_", "Lazy_", "AssertCanonical_", "SplitLowBits_"}, MaxLines: veModuleMaxLines},
		{Module: "Curve", Prefixes: []string{
			"AssertOnCurve_", "Add_", "Triple_", "HalfTangentSlope_", "AssertDistinctX_", "AssertDistinctSlope_",
			"QuadrupleAndAddLazy_", "ScalarMulChecked_", "CombSelect_", "CombChainStep_", "CompleteAdd_",
			"ScalarMulBase_", "CompressedPacking_",
		}, MaxLines: veModuleMaxLines},
		{Module: "Aes", Prefixes: []string{"Aes"}, MaxLines: veModuleMaxLines},
		{Module: "Kdf", Prefixes: []string{"Poseidon", "FieldBytesBE_"}, MaxLines: veModuleMaxLines},
	},
}

const veModuleMaxLines = 40000

// veConstantSeed lists the named constants K_0, K_1, ... of the committed
// extraction, one decimal value per line. Seeding the extractor with it keeps
// every K_i stable (the Lean proofs cite some by name) when circuits are
// added; new constants continue after the seed. TestVEConstantSeedIsComplete
// requires it to cover every constant (UPDATE_VE_CONSTANTS=1 rewrites it).
//
//go:embed ve_constants.txt
var veConstantSeed string

func extractVE() (map[string]string, error) {
	opts := veExportOptions
	opts.SeedConstants = strings.Fields(veConstantSeed)
	return leanextractor.ExtractCircuitModules(
		opts,
		veModuleLayout,
		"ZolanaVE",
		ecc.BN254,
		&ve.FieldMulCheck{},
		&ve.GuardedAdd{},
		&ve.AgreeKey{},
		&ve.DerivePublicKey{},
		&ve.AesCtrBlock{},
		&ve.KeySchedule{},
		&ve.Envelope{},
		&ve.EnvelopeMerge{},
	)
}

// ExtractVELean extracts the verifiable-encryption circuits into Lean modules
// under the Lake root leanRoot: VerifiableEncryption/Circuit.lean imports the
// modules in VerifiableEncryption/Circuit/. Stale modules are removed first.
// The output is committed; CI re-extracts and diffs it. It returns the bytes
// written.
func ExtractVELean(leanRoot string) (int, error) {
	modules, err := extractVE()
	if err != nil {
		return 0, err
	}
	moduleDir := filepath.Join(leanRoot, filepath.FromSlash(strings.ReplaceAll(veModuleLayout.Root, ".", "/")))
	stale, err := filepath.Glob(filepath.Join(moduleDir, "*.lean"))
	if err != nil {
		return 0, err
	}
	for _, path := range stale {
		if err := os.Remove(path); err != nil {
			return 0, err
		}
	}
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		return 0, err
	}
	written := 0
	for module, source := range modules {
		path := filepath.Join(leanRoot, filepath.FromSlash(strings.ReplaceAll(module, ".", "/"))+".lean")
		if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
			return 0, err
		}
		written += len(source)
	}
	return written, nil
}
