// The spread gadget is sound against a malicious prover because of three facts,
// each pinned by a test:
//
//  1. Every lookup proves the (index, result) pair is a table row, so a wrong
//     result at a valid index is rejected by the log-derivative equality
//     (TestLookupTablesRejectForgedResultAtValidIndex, TestCTRRejectsForgedKeyByteSpread).
//  2. laneChunksHint is pinned by the recomposition assert and chunk membership
//     together; dropping either admits a forged decomposition
//     (lane_parity_mutation_test.go).
//  3. substitute selects a region by offset, so its index must already be a
//     byte; an unconstrained index escapes into the next region
//     (TestSubstituteRegionEscapeNeedsByteIndex).
package aes

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/prover/prover-test/hintattack"
)

type lookupForgeryCircuit struct {
	SubstitutionIndex, ByteIndex, ChunkIndex frontend.Variable
}

func (c *lookupForgeryCircuit) Define(api frontend.API) error {
	t := sharedSpreadTables(api)
	t.substitute(0, c.SubstitutionIndex)
	t.spreadByte(c.ByteIndex)
	t.chunks.Lookup(c.ChunkIndex)
	return nil
}

func TestLookupTablesRejectForgedResultAtValidIndex(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &lookupForgeryCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(&lookupForgeryCircuit{SubstitutionIndex: 0x3c, ByteIndex: 0xa5, ChunkIndex: 777}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(witness); err != nil {
		t.Fatal(err)
	}
	for name, size := range map[string]uint64{"substitution": substitutionSize, "bytes": tableRegionSize, "chunks": chunkRadix} {
		t.Run(name, func(t *testing.T) {
			forged := hintattack.ForgeLookupResult(t, cs, size)
			hintattack.RequireConstraintRejection(t, cs.IsSolved(witness, hintattack.SkipMissingLookupQueries(t)))
			if forged.Load() != 1 {
				t.Fatalf("forged %d lookups, want exactly one", forged.Load())
			}
		})
	}
}
