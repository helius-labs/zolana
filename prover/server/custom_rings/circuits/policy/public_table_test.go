package policy

import (
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func fullTwoByThreeStatement(t *testing.T, anonymous bool) *statement {
	s := newStatement(t, defaultFixture())
	s.curatorRegistry = assetField(t, fill(0x12))
	s.anonymous = anonymous
	s.inputs[0].Amount = big.NewInt(600)
	s.inputs[1] = s.inputs[0]
	s.inputs[1].Blinding = big.NewInt(0x61)
	s.outputs[0].Amount = big.NewInt(400)
	s.outputs[1] = s.outputs[0]
	s.outputs[1].Blinding = big.NewInt(0x62)
	s.outputs = append(s.outputs, s.outputs[0])
	s.outputs[2].Blinding = big.NewInt(0x63)
	s.recipientKeys[1], s.recipientKeys[2] = s.recipientKeys[0], s.recipientKeys[0]
	for i := range s.sources {
		s.sources[i] = source{listId: int64(i + 1), registry: big.NewInt(0)}
	}
	s.sources[listFrozen-1].registry = s.curatorRegistry
	s.rules = make([]rule, NRules)
	for i := range s.rules {
		s.rules[i] = rule{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listAllow) | 1<<(i%NSources)}
	}
	s.rules[8] = rule{subject: SubjectSender, mode: ModeAbsent, mask: listMask(listFrozen)}
	s.rules[9] = rule{subject: SubjectAsset, mode: ModePresent, mask: listMask(listAllow)}
	s.rules[10] = rule{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listApproval), guardTag: GuardAboveAmount, threshold: 2000}
	s.rules[11] = rule{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listAllow), altMask: listMask(listBlock)}
	// Keep every row distinct, as the on-chain table validator requires.
	for i, mask := range []int64{7, 11, 19} {
		s.rules[12+i] = rule{subject: SubjectOutputOwner, mode: ModePresent, mask: mask}
	}
	s.rules[15] = rule{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listApproval, listBlock), guardTag: GuardAboveAmountByAsset}
	s.inlineAssets, s.inlineLimits = nil, nil
	s.limits = nil
	for i := 0; i < NAmountGuards; i++ {
		asset := big.NewInt(int64(100 + i))
		if i == 0 {
			asset = spptest.AsBigInt(s.outputs[0].Asset)
		}
		s.inlineAssets = append(s.inlineAssets, asset)
		s.inlineLimits = append(s.inlineLimits, 2000)
		s.limits = append(s.limits, limitRow{asset: asset, cap: 2000, cosign: 1800})
	}
	s.keyEscrow = true
	s.ctHashes = []*big.Int{big.NewInt(0xc0), big.NewInt(0xc0), big.NewInt(0xc0)}
	s.members.RegisterKey(t, spptest.AsBigInt(s.outputs[0].OwnerPkHash), spptest.AsBigInt(s.outputs[0].NullifierPk), s.ctHashes[0])
	return s
}

func TestPublicTableFullPolicyRejectsViolations(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &PublicTableTwoByThreeCircuit{}, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	for _, attack := range []struct {
		name   string
		change func(*statement)
	}{
		{"recipient not approved", func(s *statement) { s.setLists(t, s.members, spptest.AsBigInt(s.outputs[0].OwnerPkHash), 0) }},
		{"sender frozen by curator", func(s *statement) { s.setLists(t, s.curator, s.sender, listMask(listFrozen)) }},
		{"mint not approved", func(s *statement) { s.setLists(t, s.members, spptest.AsBigInt(s.outputs[0].Asset), 0) }},
		{"outflow above cap", func(s *statement) { s.limits[0].cap = 1199 }},
		{"missing approval", func(s *statement) { s.limits[0].cosign = 1199 }},
		{"false approval", func(s *statement) { s.approval = true }},
		{"per asset guard exceeded", func(s *statement) { s.inlineLimits[0] = 1199 }},
		{"scalar guard exceeded", func(s *statement) { s.rules[10].threshold = 1199 }},
		{"wrong escrowed key", func(s *statement) { s.outputs[0].NullifierPk = big.NewInt(1) }},
		{"wrong escrow ciphertext", func(s *statement) { s.ctHashes[0] = big.NewInt(1) }},
		{"second sender under outflow limits", func(s *statement) { s.inputs[1].OwnerPkHash = spptest.AsBigInt(s.outputs[0].OwnerPkHash) }},
	} {
		t.Run(attack.name, func(t *testing.T) {
			s := fullTwoByThreeStatement(t, false)
			attack.change(s)
			w := publicTableAssignment(t, s, false)
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.IsSolved(witness); err == nil {
				t.Fatal("policy violation accepted with a freshly recomputed public statement")
			}
		})
	}
}

func publicTableAssignment(t *testing.T, s *statement, delegate bool) *PublicTableTwoByThreeCircuit {
	t.Helper()
	p := s.assignment(t)
	w := &PublicTableTwoByThreeCircuit{
		Circuit: TwoByThreeCircuit{Policy: *p, Anonymous: s.anonymous, Delegate: delegate},
		Table: PublicTable{Hash: s.policyHash, Sources: p.Sources, Rules: p.Rules, PolicyLen: p.PolicyLen,
			InlineAssets: p.InlineAssets, InlineLimits: p.InlineLimits, InlineCount: p.InlineCount,
			Limits: p.Limits, LimitCount: p.LimitCount},
		TreeHash: spptest.MustTreeSlotsHashChain(t, s.treeSlots(t)),
	}
	var subjects []*big.Int
	for _, slot := range append(append([]UtxoWires{}, s.inputs...), s.outputs...) {
		if spptest.AsBigInt(slot.Domain).Int64() == protocol.UtxoDomain {
			subjects = append(subjects, spptest.AsBigInt(slot.OwnerPkHash))
		}
	}
	for _, output := range s.outputs {
		if spptest.AsBigInt(output.Domain).Int64() == protocol.UtxoDomain {
			subjects = append(subjects, spptest.AsBigInt(output.Asset))
		}
	}
	for i, tree := range []*spptest.MemberRegistry{s.members, s.curator} {
		var openings []registry.SparseOpening
		if i == 0 || s.anyForeign() {
			for _, subject := range subjects {
				o := tree.Opening(subject)
				openings = append(openings, registry.SparseOpening{Index: o.Index, Leaf: o.Record.Hash(t), Path: o.Path})
			}
		}
		var err error
		w.Registry[i], err = registry.BuildSparseSubtree(openings)
		if err != nil {
			t.Fatal(err)
		}
	}
	return w
}

func TestPublicTableTwoByThreeProofs(t *testing.T) {
	for _, mode := range []string{"ordinary", "anonymous", "delegate"} {
		t.Run(mode, func(t *testing.T) {
			anonymous, delegate := mode == "anonymous", mode == "delegate"
			c := &PublicTableTwoByThreeCircuit{Circuit: TwoByThreeCircuit{Anonymous: anonymous, Delegate: delegate}}
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			if cs.GetNbConstraints() >= 100000 {
				t.Fatalf("budget: %d constraints", cs.GetNbConstraints())
			}
			commitments := cs.GetCommitments().(constraint.Groth16Commitments)
			if len(commitments) != 1 || commitments[0].NbPublicCommitted != 0 {
				t.Fatal("unsupported commitment shape")
			}
			s := fullTwoByThreeStatement(t, anonymous)
			w := publicTableAssignment(t, s, delegate)
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.IsSolved(witness); err != nil {
				t.Fatal(err)
			}
			pk, vk, err := groth16.Setup(cs)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			proof, err := groth16.Prove(cs, pk, witness)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			public, err := witness.Public()
			if err != nil {
				t.Fatal(err)
			}
			if err := groth16.Verify(proof, vk, public); err != nil {
				t.Fatal(err)
			}
			derived, err := AssignPublicTable(&w.Circuit.Policy, anonymous, delegate)
			if err != nil {
				t.Fatal(err)
			}
			derivedWitness, err := frontend.NewWitness(derived, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			derivedPublic, err := derivedWitness.Public()
			if err != nil {
				t.Fatal(err)
			}
			if err := groth16.Verify(proof, vk, derivedPublic); err != nil {
				t.Fatalf("host-derived public fields: %v", err)
			}
			if err := cs.IsSolved(derivedWitness); err != nil {
				t.Fatalf("host-derived sparse frontier: %v", err)
			}
			t.Logf("%s: constraints=%d public=%d proving=%s", mode, cs.GetNbConstraints(), cs.GetNbPublicVariables()-1, elapsed)
			for _, attack := range []struct {
				name   string
				mutate func(*PublicTableTwoByThreeCircuit)
			}{
				{"opaque queried root", func(w *PublicTableTwoByThreeCircuit) { w.Registry[0].Expanded[0] = 0 }},
				{"wrong subtree", func(w *PublicTableTwoByThreeCircuit) { w.Registry[0].Nodes[0] = 123 }},
				{"wrong mode", func(w *PublicTableTwoByThreeCircuit) { w.Circuit.Policy.Anonymous = 1 - boolInt(anonymous) }},
				{"wrong count", func(w *PublicTableTwoByThreeCircuit) { w.Circuit.Policy.NOut = 2 }},
				{"private rule substitution", func(w *PublicTableTwoByThreeCircuit) { w.Circuit.Policy.Rules[0] = 0 }},
				{"private limit substitution", func(w *PublicTableTwoByThreeCircuit) { w.Circuit.Policy.Limits[0].Cap = 9999 }},
				{"public rule substitution", func(w *PublicTableTwoByThreeCircuit) { w.Table.Rules[0] = 0 }},
				{"public tree substitution", func(w *PublicTableTwoByThreeCircuit) { w.TreeHash = 123 }},
				{"disclosure substitution", func(w *PublicTableTwoByThreeCircuit) { w.Circuit.Policy.Salt[0] = 123 }},
			} {
				t.Run(attack.name, func(t *testing.T) {
					bad := *w
					attack.mutate(&bad)
					badWitness, err := frontend.NewWitness(&bad, ecc.BN254.ScalarField())
					if err != nil {
						t.Fatal(err)
					}
					if err := cs.IsSolved(badWitness); err == nil {
						t.Fatal("forged witness accepted")
					}
				})
			}
		})
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
