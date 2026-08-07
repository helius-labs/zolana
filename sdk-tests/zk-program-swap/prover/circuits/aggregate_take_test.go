package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"circuits/take"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	aggregateprover "zolana/prover/prover/aggregate"
	"zolana/prover/prover/common"
)

// The take circuit joins mixed aggregate batches as a slot beside transfer
// legs. The outer circuit's placeholders assume one public input and no
// commitment per uncommitted slot, so the take key must have that shape.
func TestTakeKeyFitsAnAggregateSlot(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles and sets up the take circuit")
	}
	ccs, vk := takeSystem(t)

	if commitments := len(ccs.GetCommitments().CommitmentIndexes()); commitments != 0 {
		t.Fatalf("take circuit has %d commitments, want 0", commitments)
	}
	// One public input plus the constant wire.
	if public := ccs.GetNbPublicVariables(); public != 2 {
		t.Fatalf("take circuit has %d public variables, want 2", public)
	}
	bnVk, ok := vk.(*groth16_bn254.VerifyingKey)
	if !ok {
		t.Fatalf("verifying key is %T", vk)
	}
	if len(bnVk.G1.K) != 2 {
		t.Fatalf("take key has %d IC points, want 2", len(bnVk.G1.K))
	}
}

// Compile of the take-beside-confidential outer circuit against the real take
// verifying key and the pinned confidential inner key. Proving a take leg
// needs the Rust SDK's witness construction, so this test stops at the
// compiled system and checks the counts and the single outer commitment.
func TestTakeMixedAggregateCompiles(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles a multi-million constraint circuit")
	}
	confidential := loadConfidentialSystem(t)
	_, takeVk := takeSystem(t)

	p := aggregateprover.Params{Slots: []common.AggregateSlot{
		{Inner: common.SwapTakeCircuitType},
		{Inner: common.TransferConfidentialCircuitType, NInputs: 2, NOutputs: 2},
	}}
	ccs, err := aggregateprover.R1CSAggregate(p, []groth16.VerifyingKey{takeVk, confidential.VerifyingKey})
	if err != nil {
		t.Fatal(err)
	}
	r1cs, ok := ccs.(*cs_bn254.R1CS)
	if !ok {
		t.Fatalf("compiled to %T", ccs)
	}
	if commitments := len(ccs.GetCommitments().CommitmentIndexes()); commitments != 1 {
		t.Fatalf("outer circuit has %d commitments, want 1", commitments)
	}
	t.Logf("%s: constraints=%d levels=%d", p.KeyName(), r1cs.GetNbConstraints(), len(r1cs.System.Levels))

	// The raw key file feeds light-prover setup-aggregate-mix.
	if out := os.Getenv("TAKE_VK_OUT"); out != "" {
		bnVk := takeVk.(*groth16_bn254.VerifyingKey)
		file, err := os.Create(out)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if _, err := bnVk.WriteRawTo(file); err != nil {
			t.Fatal(err)
		}
		t.Logf("take verifying key written to %s", out)
	}
}

func takeSystem(t *testing.T) (constraint.ConstraintSystem, groth16.VerifyingKey) {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &take.Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	_, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	return ccs, vk
}

func loadConfidentialSystem(t *testing.T) *common.TransferProofSystem {
	t.Helper()
	dir := os.Getenv("ZOLANA_SPP_KEYS_DIR")
	if dir == "" {
		dir = filepath.Join("..", "..", "..", "..", "prover", "server", "proving-keys")
	}
	path := filepath.Join(dir, "transfer_confidential_2_2.key")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("missing %s", path)
	}
	system, err := common.ReadSystemFromFile(path)
	if err != nil {
		t.Fatal(fmt.Errorf("read %s: %w", path, err))
	}
	ps, ok := system.(*common.TransferProofSystem)
	if !ok {
		t.Fatalf("%s read as %T", path, system)
	}
	return ps
}
