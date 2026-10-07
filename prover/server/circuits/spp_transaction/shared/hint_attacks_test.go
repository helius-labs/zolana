package shared_test

import (
	"sort"
	"testing"
	"time"

	. "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/hintattack"
	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

var hintAttackShape = protocol.Shape{NInputs: 2, NOutputs: 2}

func runTransactionRailHintAttacks(t *testing.T, circuit, assignment frontend.Circuit) {
	t.Helper()
	start := time.Now()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	system, ok := cs.(*csbn254.R1CS)
	if !ok {
		t.Fatalf("unexpected constraint system %T", cs)
	}
	names := make([]string, 0, len(system.MHintsDependencies))
	for _, name := range system.MHintsDependencies {
		names = append(names, name)
	}
	sort.Strings(names)
	t.Logf("compiled %s in %s: %d constraints", hintAttackShape, time.Since(start).Round(time.Millisecond), cs.GetNbConstraints())
	t.Logf("hints: %v", names)
	hintattack.RunHintAttacks(t, cs, func(opts ...solver.Option) error {
		w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatalf("new witness: %v", err)
		}
		return cs.IsSolved(w, opts...)
	})
	t.Logf("total %s", time.Since(start).Round(time.Millisecond))
}

func TestDefaultRingEddsaOnlyRejectsHintAttacks(t *testing.T) {
	runTransactionRailHintAttacks(t,
		MustNewDefaultRingEddsaOnlyCircuit(Shape(hintAttackShape)),
		asDefaultRingEddsaOnly(buildDefaultRingEddsaOnlyAssignment(t, hintAttackShape)),
	)
}

func TestCustomRingEddsaOnlyRejectsHintAttacks(t *testing.T) {
	assignment := buildCircuitAssignment(t, hintAttackShape)
	refreshPublicInputHash(t, assignment)
	runTransactionRailHintAttacks(t,
		MustNewCustomRingEddsaOnlyCircuit(Shape(hintAttackShape)),
		asCustomRingEddsaOnly(assignment),
	)
}

func TestCustomRingAuthorityRejectsHintAttacks(t *testing.T) {
	runTransactionRailHintAttacks(t,
		MustNewCustomRingAuthorityCircuit(Shape(hintAttackShape)),
		asCustomRingAuthority(buildRingAuthorityAssignment(t, hintAttackShape)),
	)
}
