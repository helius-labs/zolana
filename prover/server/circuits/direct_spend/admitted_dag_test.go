package directspend

import (
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func NewDAGAdmittedPayment(inputs, height int) *DAGPaymentCircuit {
	return newDAGPayment(inputs, 2, height)
}

type DAGAdmittedPayment = DAGPaymentCircuit

func TestAdmittedDAGConstraints(t *testing.T) {
	if os.Getenv("ADMITTED_DAG_COUNTS") == "" {
		t.Skip("set ADMITTED_DAG_COUNTS=1")
	}
	for _, height := range []int{10, 16} {
		t.Run(fmt.Sprint(height), func(t *testing.T) {
			c := NewDAGAdmittedPayment(512, height)
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			commitments := cs.GetCommitments().(constraint.Groth16Commitments)
			if len(commitments) != 1 || len(commitments[0].PublicAndCommitmentCommitted) != 0 || cs.GetNbPublicVariables() != 2 {
				t.Fatal("DAG payment does not match the single private BSB22 commitment verifier")
			}
			t.Logf("ADMITTED_DAG inputs=512 height=%d constraints=%d fft_domain=%d private_committed=%d", height, cs.GetNbConstraints(), ecc.NextPowerOfTwo(uint64(cs.GetNbConstraints())), len(commitments[0].PrivateCommitted))
		})
	}
}
