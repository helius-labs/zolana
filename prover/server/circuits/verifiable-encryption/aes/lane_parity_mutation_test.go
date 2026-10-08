package aes

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/prover/prover-test/hintattack"
)

type laneParityMutation uint8

const (
	laneParityIntact laneParityMutation = iota
	laneParityWithoutRecomposition
	laneParityWithoutChunkMembership
)

func init() {
	solver.RegisterHint(chunkParityHint)
}

func chunkParityHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != len(outputs) {
		return fmt.Errorf("chunk parity: %d inputs for %d outputs", len(inputs), len(outputs))
	}
	for i, chunk := range inputs {
		if !chunk.IsInt64() {
			return fmt.Errorf("chunk parity: chunk %d is not an integer", i)
		}
		outputs[i].SetInt64(int64(chunkParity(int(chunk.Int64()))))
	}
	return nil
}

func decodeWordSumMutant(t *spreadTables, spreadSum frontend.Variable, byteCount int, mutation laneParityMutation) []frontend.Variable {
	out := make([]frontend.Variable, byteCount)
	chunks, err := t.api.NewHint(laneChunksHint, 2*byteCount, spreadSum)
	if err != nil {
		panic(err)
	}
	if mutation != laneParityWithoutRecomposition {
		var recomposed frontend.Variable = 0
		weight := big.NewInt(1)
		for _, c := range chunks {
			recomposed = t.api.Add(recomposed, t.api.Mul(c, weight))
			weight = new(big.Int).Mul(weight, big.NewInt(chunkRadix))
		}
		t.api.AssertIsEqual(spreadSum, recomposed)
	}
	var nibbles []frontend.Variable
	if mutation == laneParityWithoutChunkMembership {
		nibbles, err = t.api.NewHint(chunkParityHint, len(chunks), chunks...)
		if err != nil {
			panic(err)
		}
	} else {
		nibbles = t.chunks.Lookup(chunks...)
	}
	for j := range out {
		out[j] = t.api.Add(nibbles[2*j], t.api.Mul(nibbles[2*j+1], 16))
	}
	return out
}

type laneParityMutantCircuit struct {
	Lane, Byte frontend.Variable
	mutation   laneParityMutation
}

func (c *laneParityMutantCircuit) Define(api frontend.API) error {
	t := sharedSpreadTables(api)
	t.spreadByte(1)
	t.substitute(sboxRegion, 1)
	if c.mutation == laneParityWithoutChunkMembership {
		t.chunks.Lookup(1)
	}
	api.AssertIsEqual(decodeWordSumMutant(t, c.Lane, 1, c.mutation)[0], c.Byte)
	return nil
}

func solveLaneParityMutant(t *testing.T, mutation laneParityMutation, lane, claimed int64, forge func(chunks []*big.Int), rejecting bool) error {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &laneParityMutantCircuit{mutation: mutation})
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(&laneParityMutantCircuit{Lane: lane, Byte: claimed}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	forged := func(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
		if err := laneChunksHint(field, inputs, outputs); err != nil {
			return err
		}
		forge(outputs)
		return nil
	}
	opts := []solver.Option{solver.OverrideHint(solver.GetHintID(laneChunksHint), forged)}
	if rejecting {
		hintattack.SubstituteOutOfRangeLookups(t, cs, 0)
		opts = append(opts, hintattack.SkipMissingLookupQueries(t))
	}
	return cs.IsSolved(witness, opts...)
}

func TestLaneParityChecksEachStopTheirAttack(t *testing.T) {
	zeroed := func(chunks []*big.Int) {
		for _, c := range chunks {
			c.SetInt64(0)
		}
	}
	wholeSumInChunkZero := func(chunks []*big.Int) {
		chunks[0].SetInt64(chunkRadix)
		chunks[1].SetInt64(0)
	}
	cases := []struct {
		name            string
		mutant          laneParityMutation
		lane            int64
		honest, claimed int64
		forge           func([]*big.Int)
	}{
		{"recomposition stops zeroed chunks", laneParityWithoutRecomposition, 1, 1, 0, zeroed},
		{"membership stops an oversized chunk", laneParityWithoutChunkMembership, chunkRadix, 16, 0, wholeSumInChunkZero},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := solveLaneParityMutant(t, tc.mutant, tc.lane, tc.honest, func([]*big.Int) {}, false); err != nil {
				t.Fatalf("mutant rejects the honest witness: %v", err)
			}
			hintattack.RequireConstraintRejection(t, solveLaneParityMutant(t, laneParityIntact, tc.lane, tc.claimed, tc.forge, true))
			if err := solveLaneParityMutant(t, tc.mutant, tc.lane, tc.claimed, tc.forge, false); err != nil {
				t.Fatalf("mutant still rejects the attack, so the removed check is not what stops it: %v", err)
			}
		})
	}
}

type substituteEscapeCircuit struct {
	Index   frontend.Variable
	guarded bool
}

func (c *substituteEscapeCircuit) Define(api frontend.API) error {
	t := sharedSpreadTables(api)
	t.spreadByte(1)
	t.chunks.Lookup(1)
	if c.guarded {
		t.spreadByte(c.Index)
	}
	api.AssertIsEqual(t.substitute(0, c.Index), t.substitute(1, 0))
	return nil
}

func TestSubstituteRegionEscapeNeedsByteIndex(t *testing.T) {
	solve := func(guarded bool, opts ...solver.Option) error {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &substituteEscapeCircuit{guarded: guarded})
		if err != nil {
			t.Fatal(err)
		}
		witness, err := frontend.NewWitness(&substituteEscapeCircuit{Index: tableRegionSize}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if guarded {
			hintattack.SubstituteOutOfRangeLookups(t, cs, 0)
			opts = append(opts, hintattack.SkipMissingLookupQueries(t))
		}
		return cs.IsSolved(witness, opts...)
	}
	if err := solve(false); err != nil {
		t.Fatalf("an unconstrained index must escape into the next region: %v", err)
	}
	hintattack.RequireConstraintRejection(t, solve(true))
}
