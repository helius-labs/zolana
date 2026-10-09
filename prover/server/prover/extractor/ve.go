package extractor

import (
	"github.com/consensys/gnark-crypto/ecc"
	leanextractor "github.com/reilabs/gnark-lean-extractor/v3/extractor"

	"zolana/prover/circuits/formal/ve"
)

// Vector access without bound-proof tactics and bodies split into parts of at
// most 200 operations keep every definition shallow enough to elaborate; named
// big constants keep the file small.
var veExportOptions = leanextractor.ExportOptions{VectorGet: true, MaxBodyApps: 200, NamedConstantDigits: 20}

// ExtractVELean extracts the verifiable-encryption circuits into one Lean
// source file. The output is committed as
// formal-verification/VerifiableEncryption/Circuit.lean; CI re-extracts and
// diffs it.
func ExtractVELean() (string, error) {
	return leanextractor.ExtractCircuitsWith(
		veExportOptions,
		"ZolanaVE",
		ecc.BN254,
		&ve.FieldMulCheck{},
		&ve.GuardedAdd{},
		&ve.AgreeKey{},
		&ve.DerivePublicKey{},
		&ve.AesCtrBlock{},
		&ve.KeySchedule{},
		&ve.Envelope{},
	)
}
