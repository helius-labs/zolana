package nullifier_fold

import (
	"math/big"
	"testing"

	foldcircuit "zolana/prover/circuits/nullifier_fold"

	"zolana/prover/circuits/gadget"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

const (
	testHeight    = 40
	testBatchSize = 4
	testRun       = 2
)

// appendCircuit stands in for BatchAddressTreeAppendCircuit with the same
// single public input, which is all the fold reads. Standing in keeps the test
// off a 40-deep Merkle circuit while still exercising a real proving system.
type appendCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	OldRoot       frontend.Variable
	NewRoot       frontend.Variable
	HashchainHash frontend.Variable
	StartIndex    frontend.Variable
}

func (c *appendCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, []frontend.Variable{
		c.OldRoot, c.NewRoot, c.HashchainHash, c.StartIndex,
	}))
	return nil
}

func innerSystem(t *testing.T) *common.BatchProofSystem {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &appendCircuit{})
	if err != nil {
		t.Fatalf("compile inner: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup inner: %v", err)
	}
	return &common.BatchProofSystem{
		CircuitType:      common.BatchAddressAppendCircuitType,
		TreeHeight:       testHeight,
		BatchSize:        testBatchSize,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}
}

func proveAppend(t *testing.T, inner *common.BatchProofSystem, oldRoot, newRoot, hashchain, startIndex int64) Append {
	t.Helper()
	o, n := big.NewInt(oldRoot), big.NewInt(newRoot)
	h, s := big.NewInt(hashchain), big.NewInt(startIndex)
	public, err := HashChain([]*big.Int{o, n, h, s})
	if err != nil {
		t.Fatalf("public input: %v", err)
	}

	full, err := frontend.NewWitness(&appendCircuit{
		PublicInputHash: public, OldRoot: o, NewRoot: n, HashchainHash: h, StartIndex: s,
	}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	proof, err := groth16.Prove(inner.ConstraintSystem, inner.ProvingKey, full)
	if err != nil {
		t.Fatalf("prove append: %v", err)
	}
	pub, err := full.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}
	return Append{
		Proof: proof, PublicWitness: pub,
		OldRoot: o, NewRoot: n, HashchainHash: h, StartIndex: s,
	}
}

// The fold proof must verify against its own key on the span hash the forester
// program recomputes. Anything else and the on-chain path cannot accept it.
func TestProveFoldVerifiesAgainstTheSpanHash(t *testing.T) {
	inner := innerSystem(t)
	ps, err := SetupFold(Params{TreeHeight: testHeight, BatchSize: testBatchSize, Run: testRun}, inner)
	if err != nil {
		t.Fatalf("setup fold: %v", err)
	}

	run := []Append{
		proveAppend(t, inner, 100, 200, 11, 0),
		proveAppend(t, inner, 200, 300, 22, testBatchSize),
	}
	proof, err := ProveFold(ps, run)
	if err != nil {
		t.Fatalf("prove fold: %v", err)
	}

	span, err := FoldInputHash(run)
	if err != nil {
		t.Fatalf("span hash: %v", err)
	}
	public, err := frontend.NewWitness(
		&foldcircuit.Circuit{FoldInputHash: span},
		ecc.BN254.ScalarField(),
		frontend.PublicOnly(),
	)
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}
	if err := groth16.Verify(proof.Proof, ps.VerifyingKey, public); err != nil {
		t.Fatalf("verify fold: %v", err)
	}
}

// A mislabelled span is caught before proving, so the caller sees which append
// is wrong instead of an unsatisfiable constraint system.
func TestProveFoldRejectsASpanTheProofDidNotCommitTo(t *testing.T) {
	inner := innerSystem(t)
	ps, err := SetupFold(Params{TreeHeight: testHeight, BatchSize: testBatchSize, Run: testRun}, inner)
	if err != nil {
		t.Fatalf("setup fold: %v", err)
	}

	run := []Append{
		proveAppend(t, inner, 100, 200, 11, 0),
		proveAppend(t, inner, 200, 300, 22, testBatchSize),
	}
	run[1].NewRoot = big.NewInt(999)

	if _, err := ProveFold(ps, run); err == nil {
		t.Fatal("a restated span was accepted")
	}
}

func TestProveFoldRejectsAWrongRunLength(t *testing.T) {
	inner := innerSystem(t)
	ps, err := SetupFold(Params{TreeHeight: testHeight, BatchSize: testBatchSize, Run: testRun}, inner)
	if err != nil {
		t.Fatalf("setup fold: %v", err)
	}

	for _, count := range []int{0, 1, 3} {
		if _, err := ProveFold(ps, make([]Append, count)); err == nil {
			t.Errorf("%d appends were accepted against a run of %d", count, ps.Run)
		}
	}
}

// The outer key must be the shape the shielded pool already verifies, one
// public input and one BSB22 commitment over private wires. Then the fold needs
// no new on-chain verifier. The recursion verifier commits internally, so the
// commitment is present whether or not the fold itself uses lookups.
func TestFoldVerifyingKeyMatchesTheOnChainVerifier(t *testing.T) {
	inner := innerSystem(t)
	ps, err := SetupFold(Params{TreeHeight: testHeight, BatchSize: testBatchSize, Run: testRun}, inner)
	if err != nil {
		t.Fatalf("setup fold: %v", err)
	}

	vk, ok := ps.VerifyingKey.(*groth16bn254.VerifyingKey)
	if !ok {
		t.Fatalf("verifying key is %T", ps.VerifyingKey)
	}
	if len(vk.CommitmentKeys) != 1 {
		t.Fatalf("fold key has %d commitments, want 1", len(vk.CommitmentKeys))
	}
	// An empty committed set means the commitment covers private wires only.
	// The groth16_solana parser rejects a commitment over a public input.
	if committed := vk.PublicAndCommitmentCommitted; len(committed) != 1 || len(committed[0]) != 0 {
		t.Errorf("commitment covers public inputs %v, want none", committed)
	}

	// NbPublicWitness counts the commitment wire gnark appends. Subtracting it
	// leaves the circuit's own public inputs. The fold declares one, the span hash.
	declared := ps.VerifyingKey.NbPublicWitness() - len(vk.CommitmentKeys)
	if declared != 1 {
		t.Errorf("fold key declares %d public inputs, want 1", declared)
	}

	// groth16_solana requires vk_ic.len() == public_inputs + 2 for a BSB22 key.
	// Same shape as the aggregate key, so the fold needs no new verifier.
	if want := declared + 2; len(vk.G1.K) != want {
		t.Errorf("fold key has %d IC points, want %d", len(vk.G1.K), want)
	}
}

func TestParamsRejectAnUnamortizedRun(t *testing.T) {
	for _, run := range []uint32{0, 1, MaxRun + 1} {
		p := Params{TreeHeight: testHeight, BatchSize: testBatchSize, Run: run}
		if err := p.Validate(); err == nil {
			t.Errorf("run %d was accepted", run)
		}
	}
}

// The key name selects the file, so it must name every field the outer key is
// specialized on. Two folds that differ in any of them are different circuits.
func TestKeyNameNamesEveryField(t *testing.T) {
	p := Params{TreeHeight: testHeight, BatchSize: testBatchSize, Run: testRun}
	if got, want := p.KeyName(), "nullifier-fold_40_4_r2.key"; got != want {
		t.Errorf("key name is %q, want %q", got, want)
	}
}
