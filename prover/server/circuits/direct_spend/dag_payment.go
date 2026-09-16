package directspend

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/iden3/go-iden3-crypto/poseidon"

	"zolana/prover/circuits/gadget"
)

const DAGTreeHeight = 10

type DAGPair struct {
	Left, Right, Parent frontend.Variable
}

type DAGPaymentCircuit struct {
	AdmittedPaymentCircuit `json:"AdmittedPaymentCircuit"`
	Levels                 [][]DAGPair
	LeafRef                []frontend.Variable
	Height                 int `gnark:"-" json:"-"`
}

func NewDAGPayment(inputs, outputs int) *DAGPaymentCircuit {
	return newDAGPayment(inputs, outputs, DAGTreeHeight)
}

func newDAGPayment(inputs, outputs, height int) *DAGPaymentCircuit {
	c := &DAGPaymentCircuit{
		AdmittedPaymentCircuit: *NewAdmittedPayment(inputs, outputs),
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

func (c *DAGPaymentCircuit) Define(api frontend.API) error {
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
	return c.AdmittedPaymentCircuit.constrainCertificateDomain(api, AdmittedDAGPaymentDomain, func(certificate *Certificate) error {
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

func emptyStateRoots() ([]*big.Int, error) {
	result := make([]*big.Int, 32)
	result[0] = new(big.Int)
	for i := 1; i < len(result); i++ {
		var err error
		result[i], err = poseidon.Hash([]*big.Int{result[i-1], result[i-1]})
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
