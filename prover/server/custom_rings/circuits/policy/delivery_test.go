package policy

import (
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func solveShape(t *testing.T, cs constraint.ConstraintSystem, w *ShapeCircuit, accepted bool) {
	t.Helper()
	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	err = cs.IsSolved(witness)
	if accepted && err != nil {
		t.Fatalf("valid witness rejected: %v", err)
	}
	if !accepted && err == nil {
		t.Fatal("invalid witness accepted")
	}
}

// An anonymous shaped key proves every ring output body and chains it at the base index.
func TestAnonymousShapeDeliversEveryRingOutput(t *testing.T) {
	shape := common.RingPolicyShape{Shape: protocol.Shape{NInputs: 2, NOutputs: 2}, Anonymous: true}
	cs := compileShape(t, shape)
	s := shapeStatement(t, shape, 2, 2)
	bodies := ringaudit.BodyHashes(t, s.auditStatement(t))
	for i, body := range bodies {
		if body.Sign() == 0 {
			t.Fatalf("slot %d publishes no body", i)
		}
	}
	elements := s.policyChainElements(t)
	if len(elements) != base.BaseElements+9 {
		t.Fatalf("policy statement has %d elements", len(elements))
	}
	if elements[base.BodyChainIndex].Cmp(spptest.MustHashChain4(t, bodies)) != 0 {
		t.Fatal("the statement does not chain the published bodies")
	}
	solveShape(t, cs, shapeAssignment(t, s, shape), true)

	flip := func(v frontend.Variable) frontend.Variable { return v.(int) ^ 1 }
	for name, edit := range map[string]func(*ShapeCircuit){
		"ciphertext byte": func(c *ShapeCircuit) {
			c.Policy.Delivery.Outputs[1].Ciphertext[7] = flip(c.Policy.Delivery.Outputs[1].Ciphertext[7])
		},
		"asset address": func(c *ShapeCircuit) {
			c.Policy.Delivery.Outputs[0].AssetAddress[0] = flip(c.Policy.Delivery.Outputs[0].AssetAddress[0])
		},
		"ring program id":      func(c *ShapeCircuit) { c.Policy.Delivery.RingProgramID[0] = flip(c.Policy.Delivery.RingProgramID[0]) },
		"body of another slot": func(c *ShapeCircuit) { c.Policy.Delivery.Outputs[0] = c.Policy.Delivery.Outputs[1] },
		"body chain": func(c *ShapeCircuit) {
			tampered := append([]*big.Int{}, elements...)
			tampered[base.BodyChainIndex] = new(big.Int).Add(tampered[base.BodyChainIndex], big.NewInt(1))
			c.Policy.PublicInputHash = spptest.MustHashChain(t, tampered)
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := shapeAssignment(t, s, shape)
			edit(w)
			solveShape(t, cs, w, false)
		})
	}
}

func TestAnonymousDeliveryCostPerShape(t *testing.T) {
	for _, shape := range common.RingPolicyShapes {
		if !shape.Anonymous || shape.Subtree {
			continue
		}
		if testing.Short() && !(shape.NInputs == 1 && shape.NOutputs == 2 || shape.NInputs == 2 && shape.NOutputs == 4 || shape.NInputs == 12) {
			continue
		}
		t.Run(string(shape.CircuitType()), func(t *testing.T) {
			with := compileShape(t, shape).GetNbConstraints()
			circuit := &undeliveredShape{*NewShapeCircuit(shape.NInputs, shape.NOutputs, shape.Anonymous, shape.Delegate, shape.Subtree)}
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s total=%d delivery=%d", shape.CircuitType(), with, with-cs.GetNbConstraints())
		})
	}
}

type undeliveredShape struct{ ShapeCircuit }

func (c *undeliveredShape) Define(api frontend.API) error {
	return c.define(api, func(a base.Audit, api frontend.API, rc frontend.Rangechecker, tx base.AuditTx, _ base.Delivery) [base.BaseElements]frontend.Variable {
		elements := a.Define(api, rc, tx)
		return [base.BaseElements]frontend.Variable(slices.Insert(elements[:], base.BodyChainIndex, frontend.Variable(0)))
	})
}
