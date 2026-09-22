package policy

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// groth16-solana accepts exactly one BSB22 commitment over private wires.
func TestKeyRegisterCommitmentShape(t *testing.T) {
	cs, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		&KeyRegisterCircuit{},
		frontend.WithCompressThreshold(300),
	)
	if err != nil {
		t.Fatal(err)
	}
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok {
		t.Fatalf("unexpected commitments type %T", cs.GetCommitments())
	}
	if len(commitments) != 1 {
		t.Fatalf("expected 1 BSB22 commitment, got %d", len(commitments))
	}
	if got := commitments[0].NbPublicCommitted; got != 0 {
		t.Fatalf("expected 0 public committed wires, got %d", got)
	}
	t.Logf("register_key: %d constraints, 1 commitment over %d private wires",
		cs.GetNbConstraints(), len(commitments[0].PrivateCommitted))
}
