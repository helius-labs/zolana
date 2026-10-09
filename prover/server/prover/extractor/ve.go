package extractor

import (
	"github.com/consensys/gnark-crypto/ecc"
	leanextractor "github.com/reilabs/gnark-lean-extractor/v3/extractor"

	"zolana/prover/circuits/formal/ve"
)

// ExtractVELean extracts the verifiable-encryption circuits into one Lean
// source file. The output is committed as
// formal-verification/VerifiableEncryption/Circuit.lean; CI re-extracts and
// diffs it.
func ExtractVELean() (string, error) {
	return leanextractor.ExtractCircuits(
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
