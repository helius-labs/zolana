package directspend

import (
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/lookup/logderivlookup"

	"zolana/prover/circuits/gadget"
)

type DAGPair struct {
	Left, Right, Parent frontend.Variable
}

type DAGAdmittedPayment struct {
	AdmittedPaymentCircuit
	Levels  [][]DAGPair
	LeafRef []frontend.Variable
	Height  int `gnark:"-"`
}

func NewDAGAdmittedPayment(inputs, height int) *DAGAdmittedPayment {
	c := &DAGAdmittedPayment{
		AdmittedPaymentCircuit: *NewAdmittedPayment(inputs, 2),
		Levels:                 make([][]DAGPair, 32), LeafRef: make([]frontend.Variable, inputs), Height: height,
	}
	for level := range c.Levels {
		c.Levels[level] = make([]DAGPair, min(inputs, 1<<max(0, height-level-1)))
	}
	for i := range c.Certificate.Notes {
		c.Certificate.Notes[i].Path = nil
	}
	return c
}

func (c *DAGAdmittedPayment) Define(api frontend.API) error {
	if c.Height < 1 || c.Height > 32 || len(c.Levels) != 32 || len(c.LeafRef) != len(c.Certificate.Notes) {
		return fmt.Errorf("invalid DAG payment shape")
	}
	empty, err := emptyStateRoots()
	if err != nil {
		return err
	}
	var hashes, indices logderivlookup.Table
	for level := 31; level >= 0; level-- {
		nextHashes, nextIndices := logderivlookup.New(api), logderivlookup.New(api)
		for _, node := range c.Levels[level] {
			if level >= c.Height {
				api.AssertIsEqual(node.Right, empty[level])
				api.AssertIsEqual(node.Parent, 0)
			}
			hash := gadget.PoseidonHash(api, []frontend.Variable{node.Left, node.Right})
			var index frontend.Variable = 0
			if level == 31 {
				api.AssertIsEqual(hash, c.Certificate.StateRoot)
				api.AssertIsEqual(node.Parent, 0)
			} else {
				api.AssertIsEqual(hash, hashes.Lookup(node.Parent)[0])
				index = indices.Lookup(node.Parent)[0]
			}
			nextHashes.Insert(node.Left)
			nextHashes.Insert(node.Right)
			nextIndices.Insert(api.Mul(index, 2))
			nextIndices.Insert(api.Add(api.Mul(index, 2), 1))
		}
		hashes, indices = nextHashes, nextIndices
	}
	return c.AdmittedPaymentCircuit.constrainCertificate(api, func(certificate *Certificate) error {
		return certificate.constrainMembership(api, func(i int, note Note, hash, active frontend.Variable) error {
			if len(note.Path) != 0 {
				return fmt.Errorf("DAG payment contains an unused path")
			}
			api.ToBinary(note.Index, c.Height)
			api.AssertIsEqual(api.Mul(active, api.Sub(hash, hashes.Lookup(c.LeafRef[i])[0])), 0)
			api.AssertIsEqual(api.Mul(active, api.Sub(note.Index, indices.Lookup(c.LeafRef[i])[0])), 0)
			return nil
		})
	})
}

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
