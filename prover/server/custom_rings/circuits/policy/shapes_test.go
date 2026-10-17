package policy

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func shapeStatement(t *testing.T, shape common.RingPolicyShape, nIn, nOut int) *statement {
	t.Helper()
	s := fullTwoByThreeStatement(t, shape.Anonymous)
	input, output, ct := s.inputs[0], s.outputs[0], s.ctHashes[0]
	s.inputs, s.outputs, s.ctHashes = nil, nil, nil
	for i := 0; i < nIn; i++ {
		w := input
		w.Amount = big.NewInt(int64(nOut))
		w.Blinding = big.NewInt(int64(500 + i))
		s.inputs = append(s.inputs, w)
	}
	for i := 0; i < nOut; i++ {
		w := output
		w.Amount = big.NewInt(int64(nIn))
		w.Blinding = big.NewInt(int64(700 + i))
		s.outputs = append(s.outputs, w)
		s.ctHashes = append(s.ctHashes, ct)
		if shape.Anonymous {
			s.recipientKeys[i] = s.recipientKeys[0]
		}
	}
	return s
}

func shapeAssignment(t *testing.T, s *statement, shape common.RingPolicyShape) *ShapeCircuit {
	t.Helper()
	inputs, outputs, ctHashes := s.inputs, s.outputs, s.ctHashes
	// Assign shared fields using the frozen legacy layout, then replace only its
	// unused transaction fields with the dynamic witness owned by the new key.
	s.inputs, s.outputs, s.ctHashes = inputs[:min(len(inputs), NInputs)], outputs[:min(len(outputs), NOutputs)], ctHashes[:min(len(ctHashes), NOutputs)]
	p := s.assignment(t)
	s.inputs, s.outputs, s.ctHashes = inputs, outputs, ctHashes
	s.updateHashes(t)
	p.PublicInputHash, p.PrivateTxHash = s.publicInputHash, s.privateTxHash
	p.Audit = s.auditStatement(t).Audit
	p.NIn, p.NOut = len(inputs), len(outputs)
	c := NewShapeCircuit(shape.NInputs, shape.NOutputs, shape.Anonymous, shape.Delegate, shape.Subtree)
	c.Policy = *p
	for i := range c.Inputs {
		c.Inputs[i] = zeroOpening()
		if i < len(inputs) {
			c.Inputs[i] = inputs[i]
		}
	}
	for i := range c.Outputs {
		c.Outputs[i] = OutputWires{UtxoWires: zeroOpening(), CtHash: 0}
		if i < len(outputs) {
			c.Outputs[i] = OutputWires{UtxoWires: outputs[i], CtHash: ctHashes[i]}
		}
	}
	for i := range c.Subjects {
		c.Subjects[i], c.ForeignSubjects[i] = zeroMemberOpening(), zeroMemberOpening()
	}
	set := func(index int, member *big.Int) {
		c.Subjects[index] = openingWires(s.members.Opening(member))
		if s.anyForeign() {
			c.ForeignSubjects[index] = openingWires(s.curator.Opening(member))
		}
	}
	for i, input := range inputs {
		if spptest.AsBigInt(input.Domain).Int64() == protocol.UtxoDomain {
			set(i, spptest.AsBigInt(input.OwnerPkHash))
		}
	}
	for i, output := range outputs {
		if spptest.AsBigInt(output.Domain).Int64() == protocol.UtxoDomain {
			set(shape.NInputs+i, spptest.AsBigInt(output.OwnerPkHash))
			set(shape.NInputs+shape.NOutputs+i, spptest.AsBigInt(output.Asset))
		}
	}
	c.Policy.Dynamic = &c.ShapeWires
	if shape.Subtree {
		c.Policy.RegistrySubtreeDepth = 3
	}
	public, err := AssignPublicTable(&c.Policy, shape.Anonymous, shape.Delegate)
	if err != nil {
		t.Fatal(err)
	}
	c.Table, c.TreeHash = public.Table, public.TreeHash
	if shape.Subtree {
		copy(c.Registry, public.Registry[:])
	}
	return c
}

func compileShape(t *testing.T, shape common.RingPolicyShape) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, NewShapeCircuit(shape.NInputs, shape.NOutputs, shape.Anonymous, shape.Delegate, shape.Subtree), frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	if cs.GetNbPublicVariables() != 79 {
		t.Fatalf("got %d public variables", cs.GetNbPublicVariables())
	}
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok || len(commitments) != 1 || len(commitments[0].PublicAndCommitmentCommitted) != 0 {
		t.Fatal("must have one private commitment")
	}
	t.Logf("%s constraints=%d", shape.CircuitType(), cs.GetNbConstraints())
	return cs
}

func TestShapedPoliciesAllSupportedCapacities(t *testing.T) {
	for _, shape := range common.RingPolicyShapes {
		t.Run(string(shape.CircuitType()), func(t *testing.T) {
			cs := compileShape(t, shape)
			// Every capacity is populated with live notes, all sixteen policy rules,
			// curator sources, escrow and outflow rows remain enabled.
			s := shapeStatement(t, shape, shape.NInputs, shape.NOutputs)
			w := shapeAssignment(t, s, shape)
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err = cs.IsSolved(witness); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestShapedPolicyRejectsCountsAndLastSlotViolations(t *testing.T) {
	shape := common.RingPolicyShape{Shape: protocol.Shape{NInputs: 8, NOutputs: 4}, Subtree: true}
	cs := compileShape(t, shape)
	cases := []struct {
		name  string
		alter func(*ShapeCircuit)
	}{
		{"zero inputs", func(c *ShapeCircuit) { c.Policy.NIn = 0 }},
		{"too many inputs", func(c *ShapeCircuit) { c.Policy.NIn = 9 }},
		{"zero outputs", func(c *ShapeCircuit) { c.Policy.NOut = 0 }},
		{"too many outputs", func(c *ShapeCircuit) { c.Policy.NOut = 5 }},
		{"wrong mode", func(c *ShapeCircuit) { c.Policy.Anonymous = 1 }},
		{"last input opening", func(c *ShapeCircuit) { c.Subjects[7].Lists = 1 }},
		{"last output opening", func(c *ShapeCircuit) { c.Subjects[11].Lists = 0 }},
		{"last asset opening", func(c *ShapeCircuit) { c.Subjects[15].Lists = 0 }},
		{"last output escrow", func(c *ShapeCircuit) { c.Outputs[3].CtHash = 1 }},
		{"foreign last input", func(c *ShapeCircuit) { c.ForeignSubjects[7].Lists = 1 }},
		{"mutated public policy", func(c *ShapeCircuit) { c.Table.Rules[15] = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := shapeAssignment(t, shapeStatement(t, shape, 8, 4), shape)
			tc.alter(w)
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if cs.IsSolved(witness) == nil {
				t.Fatal("forged witness accepted")
			}
		})
	}
	// Smaller live counts must leave the zero padding inactive in all paths.
	for _, counts := range [][2]int{{1, 1}, {2, 3}, {7, 4}} {
		t.Run(fmt.Sprint(counts), func(t *testing.T) {
			w := shapeAssignment(t, shapeStatement(t, shape, counts[0], counts[1]), shape)
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err = cs.IsSolved(witness); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A shared subtree is an optional proof optimization, never a registry size cap.
func TestGeneralShapeAcceptsScatteredRegistryAndSubtreeRejectsIt(t *testing.T) {
	shape := common.RingPolicyShape{Shape: protocol.Shape{NInputs: 2, NOutputs: 4}}
	s := shapeStatement(t, shape, 2, 3)
	// Append enough records to place the queried new sender outside the original block.
	for i := int64(1); i <= 16; i++ {
		s.setLists(t, s.members, big.NewInt(i), listMask(listAllow))
	}
	s.inputs[0].OwnerPkHash = big.NewInt(16)
	s.inputs[1].OwnerPkHash = big.NewInt(16)
	s.setLists(t, s.curator, big.NewInt(16), 0)
	w := shapeAssignment(t, s, shape)
	cs := compileShape(t, shape)
	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err = cs.IsSolved(witness); err != nil {
		t.Fatal(err)
	}
	w.Policy.RegistrySubtreeDepth = 3
	if _, err = AssignPublicTable(&w.Policy, false, false); err == nil {
		t.Fatal("scattered records accepted by shared-subtree assignment")
	}
	// The general path must still authenticate every last-slot record.
	w.Subjects[1].Path[registry.Height-1] = 1
	witness, err = frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if cs.IsSolved(witness) == nil {
		t.Fatal("forged upper path accepted")
	}
}

func TestShapedPolicyTailViolationsRebindStatement(t *testing.T) {
	// Recompute the entire transaction and public hash after tampering. This
	// checks policy semantics beyond a generic commitment mismatch.
	for _, subtree := range []bool{false, true} {
		shape := common.RingPolicyShape{Shape: protocol.Shape{NInputs: 16, NOutputs: 4}, Subtree: subtree}
		cs := compileShape(t, shape)
		for _, attack := range []struct {
			name   string
			change func(*statement)
		}{
			{"tail sender differs", func(s *statement) { s.inputs[15].OwnerPkHash = s.outputs[0].OwnerPkHash }},
			{"tail recipient not approved", func(s *statement) { s.outputs[3].OwnerPkHash = big.NewInt(123456) }},
			{"tail asset not approved", func(s *statement) { s.outputs[3].Asset = big.NewInt(123456) }},
			{"tail escrow key differs", func(s *statement) { s.outputs[3].NullifierPk = big.NewInt(1) }},
			{"tail inflow exceeds cap", func(s *statement) { s.inputs[15].Amount = big.NewInt(2001) }},
			{"tail output exceeds per-mint guard", func(s *statement) { s.outputs[3].Amount = big.NewInt(2001) }},
		} {
			t.Run(fmt.Sprintf("subtree=%v/%s", subtree, attack.name), func(t *testing.T) {
				s := shapeStatement(t, shape, 16, 4)
				attack.change(s)
				w := shapeAssignment(t, s, shape)
				witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				if cs.IsSolved(witness) == nil {
					t.Fatal("policy violation accepted after recomputing statement")
				}
			})
		}
	}
}
