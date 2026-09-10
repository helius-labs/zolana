package main

import (
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
)

// gnark 0.15 represents GKR work through custom blueprints/hints, which
// are rejected below along with every non-generic instruction.
// Export only ordinary R1Cs, in gnark's dependency order. Hints, custom
// blueprints, commitments, GKR and Println retain the original Go solver.
// Rust validates the dimensions, topology and coefficient table before use.
// The versioned bridge is internal to the generated Go/Rust pair.
func kernelSolverProgram(r1cs *cs.R1CS, infinityA, infinityB []bool) []uint32 {
	commitments, ok := r1cs.CommitmentInfo.(constraint.Groth16Commitments)
	if !ok || len(commitments) != 0 || len(r1cs.Logs) != 0 ||
		len(r1cs.MHintsDependencies) != 0 || r1cs.Type != constraint.SystemR1CS ||
		len(r1cs.Instructions) != r1cs.GetNbConstraints() {
		return nil
	}
	nInputs := len(r1cs.Public) + len(r1cs.Secret)
	nWires := nInputs + r1cs.NbInternalVariables
	if len(r1cs.Public) == 0 || len(infinityA) != nWires || len(infinityB) != nWires {
		return nil
	}
	for _, instruction := range r1cs.Instructions {
		if int(instruction.BlueprintID) >= len(r1cs.Blueprints) {
			return nil
		}
		if _, ok := r1cs.Blueprints[instruction.BlueprintID].(*constraint.BlueprintGenericR1C); !ok {
			return nil
		}
	}
	indices := func(infinity []bool) []uint32 {
		out := make([]uint32, 0, len(infinity))
		for i, isInfinity := range infinity {
			if !isInfinity {
				out = append(out, uint32(i))
			}
		}
		return out
	}
	a, b := indices(infinityA), indices(infinityB)
	program := []uint32{1, uint32(nWires), uint32(nInputs), uint32(len(r1cs.Public)),
		uint32(r1cs.GetNbConstraints()), uint32(len(a)), uint32(len(b))}
	program = append(program, a...)
	program = append(program, b...)
	var r constraint.R1C
	count := 0
	for _, level := range r1cs.Levels {
		for _, id := range level {
			if int(id) >= len(r1cs.Instructions) {
				return nil
			}
			instruction := r1cs.Instructions[id]
			blueprint := r1cs.Blueprints[instruction.BlueprintID].(*constraint.BlueprintGenericR1C)
			blueprint.DecompressR1C(&r, instruction.Unpack(&r1cs.System))
			program = append(program, instruction.ConstraintOffset, uint32(len(r.L)), uint32(len(r.R)), uint32(len(r.O)))
			for _, expression := range []constraint.LinearExpression{r.L, r.R, r.O} {
				for _, term := range expression {
					program = append(program, term.CID, term.VID)
				}
			}
			count++
		}
	}
	if count != r1cs.GetNbConstraints() {
		return nil
	}
	return program
}
