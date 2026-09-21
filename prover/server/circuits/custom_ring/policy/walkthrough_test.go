package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	base "zolana/prover/circuits/custom_ring/base"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
)

const (
	bobNotBlocked = iota
	aliceApproved
	aliceBlocked
	aliceNotFrozen
	malloryBlocked
	malloryNotApproved
)

func reviewedRecipients(t *testing.T) *statement {
	t.Helper()
	s := newStatement(t, defaultFixture())
	bob := pkField(t, allowedKey)
	alice := pkField(t, approvedKey)
	mallory := pkField(t, fill(0x77))
	s.sources = emptySources()
	s.sources[listBlock-1] = source{listId: listBlock, owner: s.curatorOwnerHash}
	s.sources[listApproval-1] = source{listId: listApproval, owner: s.ownOwnerHash}
	s.sources[listFrozen-1] = source{listId: listFrozen, owner: s.ownOwnerHash}
	s.rules = []rule{{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listApproval), altMask: listMask(listBlock)}}
	s.inlineAssets = nil
	s.inlineLimits = nil
	s.entries = []entry{
		bobNotBlocked:      {listId: listBlock, member: bob},
		aliceApproved:      {listId: listApproval, member: alice, state: EntryStateActive},
		aliceBlocked:       {listId: listBlock, member: alice, state: EntryStateActive},
		aliceNotFrozen:     {listId: listFrozen, member: alice},
		malloryBlocked:     {listId: listBlock, member: mallory, state: EntryStateActive},
		malloryNotApproved: {listId: listApproval, member: mallory},
	}
	for i := range s.entries {
		s.entries[i].content = big.NewInt(0)
	}
	s.deriveEntries(t)
	s.outputs[0].OwnerPkHash = bob
	second := s.outputs[0]
	second.OwnerPkHash = alice
	second.Blinding = big.NewInt(0x91)
	s.outputs[1] = second
	return s
}

func TestRecipientsUseDifferentAlternatives(t *testing.T) {
	s := reviewedRecipients(t)
	solve(t, testConstraintSystem(t), s.assignment(t, []int{bobNotBlocked, aliceApproved}))
}

func TestApprovalDoesNotOverrideFrozen(t *testing.T) {
	s := reviewedRecipients(t)
	s.outputs = s.outputs[1:]
	s.rules = append(s.rules, rule{subject: SubjectOutputOwner, mode: ModeAbsent, mask: listMask(listFrozen)})
	solve(t, testConstraintSystem(t), s.assignment(t, []int{aliceApproved, aliceNotFrozen}))
	rejectAssignment(t, s.assignment(t, []int{aliceApproved}))

	s.entries[aliceNotFrozen].state = EntryStateActive
	s.deriveEntries(t)
	rejectAssignment(t, s.assignment(t, []int{aliceApproved, aliceNotFrozen}))
}

func TestListFactsReuseAcrossRulesAndChange(t *testing.T) {
	s := reviewedRecipients(t)
	s.outputs = []UtxoWires{s.outputs[1], s.outputs[1], s.outputs[1]}
	for i := range s.outputs {
		s.outputs[i].Blinding = big.NewInt(int64(0x90 + i))
	}
	s.inputs[0].OwnerPkHash = s.outputs[0].OwnerPkHash
	s.rules = append(s.rules,
		rule{subject: SubjectOutputOwner, mode: ModeAbsent, mask: listMask(listFrozen)},
		rule{subject: SubjectSender, mode: ModePresent, mask: listMask(listApproval)},
	)
	c := s.assignment(t, []int{aliceApproved, aliceNotFrozen})
	solve(t, testConstraintSystem(t), c)
	c.ListFacts[1].Enabled = big.NewInt(0)
	rejectAssignment(t, c)
}

func TestBlockedRecipientWithoutApprovalFails(t *testing.T) {
	s := reviewedRecipients(t)
	s.outputs = s.outputs[:1]
	s.outputs[0].OwnerPkHash = s.entries[malloryBlocked].member
	rejectAssignment(t, s.assignment(t, []int{malloryBlocked, malloryNotApproved}))
}

func TestInlineAssetsNeedNoListFacts(t *testing.T) {
	s := newStatement(t, defaultFixture())
	s.rules = []rule{{subject: SubjectAsset, mode: ModePresent}}
	solve(t, testConstraintSystem(t), s.assignment(t, nil))

	s.inlineAssets = append(s.inlineAssets, s.inlineAssets[0])
	solve(t, testConstraintSystem(t), s.assignment(t, nil))
}

func TestDisabledListFactsNeedNotBeZero(t *testing.T) {
	s := reviewedRecipients(t)
	c := s.assignment(t, []int{bobNotBlocked, aliceApproved, aliceBlocked})
	c.ListFacts[2].Enabled = big.NewInt(0)
	c.PublicInputHash = s.publicInputHashForTargets(t, s.revocationTargets([]int{bobNotBlocked, aliceApproved}))
	solve(t, testConstraintSystem(t), c)
}

func (s *statement) deriveEntries(t *testing.T) {
	t.Helper()
	s.derived = nil
	for _, entry := range s.entries {
		s.derived = append(s.derived, deriveRecord(t, s.sources[entry.listId-1].owner, entry))
	}
	s.buildTrees(t)
}

func (s *statement) updateHashes(t *testing.T) {
	t.Helper()
	s.policyHash = s.policy().hash(t)
	inputHashes := make([]*big.Int, len(s.inputs))
	outputHashes := make([]*big.Int, len(s.outputs))
	for i, input := range s.inputs {
		inputHashes[i] = big.NewInt(0)
		if input.Domain.(*big.Int).Int64() == protocol.UtxoDomain {
			inputHashes[i] = hostUtxoHash(t, input)
		}
	}
	for i, output := range s.outputs {
		outputHashes[i] = big.NewInt(0)
		if output.Domain.(*big.Int).Int64() == protocol.UtxoDomain {
			outputHashes[i] = hostUtxoHash(t, output)
		}
	}
	s.privateTxHash = spptest.MustPoseidon(t, 6, []*big.Int{
		spptest.MustHashChain4(t, inputHashes),
		spptest.MustHashChain4(t, outputHashes),
		s.addressChain,
		s.externalDataHash,
		s.privateTxBlinding,
	})
	s.publicInputHash = s.publicInputHashForTargets(t, s.revocationTargets(nil))
}

func (s *statement) revocationTargets(listFacts []int) []*big.Int {
	targets := spptest.RepeatBigInt(big.NewInt(0), NListFacts)
	for slot, index := range listFacts {
		if s.entries[index].state == 0 {
			targets[slot] = s.derived[index].address
		} else {
			targets[slot] = s.derived[index].nullifier
		}
	}
	return targets
}

func (s *statement) publicInputHashForTargets(t *testing.T, targets []*big.Int) *big.Int {
	t.Helper()
	elements := s.auditChainElements(t)
	elements = append(elements,
		s.policyHash, s.stateRoot, s.nullifierRoot, big.NewInt(entriesTreeID),
		s.ringID, s.ownOwnerHash, new(big.Int).SetUint64(s.windowIndex), boolVar(s.approval),
	)
	elements = append(elements, targets...)
	return spptest.MustHashChain(t, elements)
}

func (s *statement) auditChainElements(t *testing.T) []*big.Int {
	t.Helper()
	wires := s.keys.AuditBlockWires(s.privateTxHash)
	for i, output := range s.outputs {
		wires.Outputs[i] = base.AuditOutputWires{
			Domain: output.Domain, TreeID: output.TreeID,
			OwnerHash: spptest.MustOwnerHash(t, spptest.AsBigInt(output.OwnerPkHash), spptest.AsBigInt(output.NullifierPk)),
			Asset:     output.Asset, Amount: output.Amount, Blinding: output.Blinding,
			DataHash: output.DataHash, RingDataHash: output.RingDataHash,
			RingProgramID: output.RingProgramID,
		}
	}
	return s.keys.ChainElementsFor(t, wires, len(s.outputs))
}

func rejectAssignment(t *testing.T, c *CustomRingPolicyCircuit) {
	t.Helper()
	witness, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := testConstraintSystem(t).IsSolved(witness); err == nil {
		t.Fatal("invalid policy witness satisfied the circuit")
	}
}
