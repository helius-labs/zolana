package policy

import (
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"

	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Chain positions that open the member's note.
const (
	chainPrivateTxHash  = 0
	chainDisclosureHash = 10
)

func memberStatement(t *testing.T, members [][32]byte, sender [32]byte) *statement {
	t.Helper()
	s := newStatement(t, defaultFixture())
	s.anonymous = true
	s.senderKey = sender
	s.sender = pkField(t, sender)
	s.inputs[0].OwnerPkHash = s.sender
	for _, member := range members {
		s.members.Update(t, pkField(t, member), big.NewInt(listMask(listAllow)), big.NewInt(0))
	}
	s.ctHashes = []*big.Int{big.NewInt(0), big.NewInt(0)}
	s.updateHashes(t)
	return s
}

func publicNames(t *testing.T, circuit frontend.Circuit) []string {
	t.Helper()
	var names []string
	leaf := reflect.TypeOf((*frontend.Variable)(nil)).Elem()
	_, err := schema.Walk(ecc.BN254.ScalarField(), circuit, leaf, func(f schema.LeafInfo, _ reflect.Value) error {
		if f.Visibility == schema.Public {
			names = append(names, f.FullName())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
}

func publicVector(t *testing.T, assignment frontend.Circuit) fr.Vector {
	t.Helper()
	public, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	return public.Vector().(fr.Vector)
}

// Only the private transaction hash and the sealed disclosure move with the member.
func TestAnonymousPolicyPublicInputsDoNotNameTheMember(t *testing.T) {
	members := [][32]byte{fill(0x81), fill(0x82)}
	statements := make([]*statement, len(members))
	for i, member := range members {
		statements[i] = memberStatement(t, members, member)
	}
	cs := testConstraintSystem(t)
	for _, s := range statements {
		solve(t, cs, s.assignment(t))
	}

	if names := publicNames(t, &CustomRingPolicyCircuit{}); !reflect.DeepEqual(names, []string{"PublicInputHash"}) {
		t.Fatalf("public wires %v", names)
	}
	first, second := statements[0].policyChainElements(t), statements[1].policyChainElements(t)
	fresh := map[int]bool{chainPrivateTxHash: true, chainDisclosureHash: true}
	for i := range first {
		if equal := first[i].Cmp(second[i]) == 0; equal == fresh[i] {
			t.Fatalf("chain element %d equal=%v", i, equal)
		}
	}

	shape := common.RingPolicyShape{Shape: protocol.Shape{NInputs: 2, NOutputs: 2}, Anonymous: true}
	names := publicNames(t, NewShapeCircuit(shape.NInputs, shape.NOutputs, shape.Anonymous, shape.Delegate, shape.Subtree))
	if names[0] != "Policy_PublicInputHash" || names[len(names)-1] != "TreeHash" {
		t.Fatalf("shaped public wires %v", names)
	}
	for _, name := range names[1 : len(names)-1] {
		if !strings.HasPrefix(name, "Table_") {
			t.Fatalf("shaped public wire %q outside the policy table", name)
		}
	}
	vectors := make([]fr.Vector, len(statements))
	for i, s := range statements {
		vectors[i] = publicVector(t, shapeAssignment(t, s, shape))
	}
	for i := range vectors[0] {
		if equal := vectors[0][i].Equal(&vectors[1][i]); equal == (i == 0) {
			t.Fatalf("shaped public input %s equal=%v", names[i], equal)
		}
	}
}
