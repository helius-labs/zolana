// Package extractor transpiles the formal-verification circuits to Lean via
// gnark-lean-extractor, for prover/server/formal-verification.
package extractor

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	leanextractor "github.com/reilabs/gnark-lean-extractor/v3/extractor"

	"zolana/prover/circuits/formal"
)

// ExtractLean extracts the inclusion and non-inclusion circuits at the given
// dimensions into a single Lean source file (returned as a string). The
// output is committed as formal-verification/FormalVerification/Circuit.lean;
// CI re-extracts and diffs it, and the Lean proofs are stated against the
// extracted definitions.
func ExtractLean(stateTreeHeight uint32, nullifierTreeHeight uint32, batchSize uint32) (string, error) {
	inclusionInPathElements := make([][]frontend.Variable, batchSize)
	nonInclusionInPathElements := make([][]frontend.Variable, batchSize)
	for i := 0; i < int(batchSize); i++ {
		inclusionInPathElements[i] = make([]frontend.Variable, stateTreeHeight)
		nonInclusionInPathElements[i] = make([]frontend.Variable, nullifierTreeHeight)
	}

	inclusionCircuit := formal.InclusionCircuit{
		Roots:          make([]frontend.Variable, batchSize),
		Leaves:         make([]frontend.Variable, batchSize),
		InPathIndices:  make([]frontend.Variable, batchSize),
		InPathElements: inclusionInPathElements,

		NumberOfUtxos: batchSize,
		Height:        stateTreeHeight,
	}

	nonInclusionCircuit := formal.NonInclusionCircuit{
		Roots:  make([]frontend.Variable, batchSize),
		Values: make([]frontend.Variable, batchSize),

		LeafLowerRangeValues:  make([]frontend.Variable, batchSize),
		LeafHigherRangeValues: make([]frontend.Variable, batchSize),

		InPathIndices:  make([]frontend.Variable, batchSize),
		InPathElements: nonInclusionInPathElements,

		NumberOfNullifiers: batchSize,
		Height:             nullifierTreeHeight,
	}

	return leanextractor.ExtractCircuits(
		"ZolanaProver",
		ecc.BN254,
		&inclusionCircuit,
		&nonInclusionCircuit,
	)
}
