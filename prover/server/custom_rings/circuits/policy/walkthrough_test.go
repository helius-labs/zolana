package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	base "github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// reviewedRecipients reads Block from the curator registry and Approval and Frozen
// from the ring's own. Bob is on no list, Alice is approved and blocked, Mallory blocked.
func reviewedRecipients(t *testing.T) *statement {
	t.Helper()
	s := newStatement(t, defaultFixture())
	bob := pkField(t, allowedKey)
	alice := pkField(t, approvedKey)
	mallory := pkField(t, fill(0x77))
	s.sources = emptySources()
	s.sources[listBlock-1] = source{listId: listBlock, registry: s.curatorRegistry}
	s.sources[listApproval-1] = source{listId: listApproval, registry: big.NewInt(0)}
	s.sources[listFrozen-1] = source{listId: listFrozen, registry: big.NewInt(0)}
	s.rules = []rule{{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listApproval), altMask: listMask(listBlock)}}
	s.inlineAssets = nil
	s.inlineLimits = nil
	s.setLists(t, s.members, bob, 0)
	s.setLists(t, s.members, alice, listMask(listApproval))
	s.setLists(t, s.curator, alice, listMask(listBlock))
	s.setLists(t, s.curator, mallory, listMask(listBlock))
	s.outputs[0].OwnerPkHash = bob
	second := s.outputs[0]
	second.OwnerPkHash = alice
	second.Blinding = big.NewInt(0x91)
	s.outputs[1] = second
	return s
}

func TestRecipientsUseDifferentAlternatives(t *testing.T) {
	s := reviewedRecipients(t)
	solve(t, testConstraintSystem(t), s.assignment(t))
}

func TestApprovalDoesNotOverrideFrozen(t *testing.T) {
	s := reviewedRecipients(t)
	alice := pkField(t, approvedKey)
	s.outputs = s.outputs[1:]
	s.rules = append(s.rules, rule{subject: SubjectOutputOwner, mode: ModeAbsent, mask: listMask(listFrozen)})
	solve(t, testConstraintSystem(t), s.assignment(t))

	s.setLists(t, s.members, alice, listMask(listApproval, listFrozen))
	rejectAssignment(t, s.assignment(t))
}

// One record serves every slot of its owner, a dropped opening fails the slot it leaves unread.
func TestRecordsServeEverySlotOfAnOwner(t *testing.T) {
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
	c := s.assignment(t)
	solve(t, testConstraintSystem(t), c)
	c.Subjects[NInputs+2] = zeroMemberOpening()
	rejectAssignment(t, c)
	c = s.assignment(t)
	c.Subjects[0] = zeroMemberOpening()
	rejectAssignment(t, c)
}

func TestBlockedRecipientWithoutApprovalFails(t *testing.T) {
	s := reviewedRecipients(t)
	s.outputs = s.outputs[:1]
	s.outputs[0].OwnerPkHash = pkField(t, fill(0x77))
	rejectAssignment(t, s.assignment(t))
}

func TestInlineAssetsNeedNoRecords(t *testing.T) {
	s := newStatement(t, defaultFixture())
	s.rules = []rule{{subject: SubjectAsset, mode: ModePresent}}
	solve(t, testConstraintSystem(t), s.assignment(t))

	s.inlineAssets = append(s.inlineAssets, s.inlineAssets[0])
	solve(t, testConstraintSystem(t), s.assignment(t))
}

// A slot that holds no UTXO leaves its openings unread.
func TestDeadSlotsIgnoreTheirOpenings(t *testing.T) {
	s := reviewedRecipients(t)
	c := s.assignment(t)
	c.Subjects[1] = openingWires(s.members.Opening(pkField(t, approvedKey)))
	c.Subjects[1].Lists = big.NewInt(0xff)
	c.ForeignSubjects[NInputs+2] = c.Subjects[1]
	solve(t, testConstraintSystem(t), c)
}

// A member off every list needs no record, the sentinel brackets it.
func TestUnlistedRecipientOpensAnAbsence(t *testing.T) {
	s := newStatement(t, defaultFixture())
	s.rules = []rule{{subject: SubjectOutputOwner, mode: ModeAbsent, mask: listMask(listBlock)}}
	s.inlineAssets = nil
	s.outputs[0].OwnerPkHash = pkField(t, fill(0x78))
	c := s.assignment(t)
	if spptest.AsBigInt(c.Subjects[NInputs].Present).Sign() != 0 {
		t.Fatal("the unlisted recipient has a record")
	}
	solve(t, testConstraintSystem(t), c)
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
	s.privateTxHash = spptest.MustPoseidon(t, 5, []*big.Int{
		spptest.MustNonZeroHashChain(t, inputHashes),
		spptest.MustNonZeroHashChain(t, outputHashes),
		s.addressChain,
		s.privateTxBlinding,
	})
	s.publicInputHash = spptest.MustHashChain(t, s.policyChainElements(t))
}

// Mirrors CustomRingPolicyPublicInput.
func (s *statement) policyChainElements(t *testing.T) []*big.Int {
	t.Helper()
	elements := s.auditChainElements(t)
	return append(elements,
		s.policyHash, spptest.MustTreeSlotsHashChain(t, s.treeSlots(t)), big.NewInt(addressTreeID),
		s.ringID, s.ownOwnerHash, boolVar(s.approval),
		boolVar(s.keyEscrow), s.members.Root(), s.foreignRoot(),
	)
}

// Chain positions after the eleven audit elements.
const (
	chainMemberRegistryRoot = 18
	chainForeignRoot        = 19
)

// rebind recomputes the statement over the roots the assignment carries, so only the openings can reject.
func (s *statement) rebind(t *testing.T, c *CustomRingPolicyCircuit) {
	t.Helper()
	elements := s.policyChainElements(t)
	elements[chainMemberRegistryRoot] = spptest.AsBigInt(c.MemberRegistryRoot)
	elements[chainForeignRoot] = spptest.AsBigInt(c.ForeignRoot)
	c.PublicInputHash = spptest.MustHashChain(t, elements)
}

func (s *statement) auditChainElements(t *testing.T) []*big.Int {
	t.Helper()
	statement := s.keys.Statement(s.privateTxHash)
	statement.Count = len(s.outputs)
	for i, output := range s.outputs {
		ownerHash := big.NewInt(0)
		if output.Domain.(*big.Int).Int64() == protocol.UtxoDomain {
			ownerHash = spptest.MustOwnerHash(t, spptest.AsBigInt(output.OwnerPkHash), spptest.AsBigInt(output.NullifierPk))
		}
		statement.Outputs[i] = base.AuditOutputWires{
			Domain: output.Domain, TreeID: output.TreeID,
			OwnerHash: ownerHash,
			Asset:     output.Asset, Amount: output.Amount, Blinding: output.Blinding,
			DataHash: output.DataHash, RingDataHash: output.RingDataHash,
			RingProgramID: output.RingProgramID,
		}
	}
	return s.keys.ChainElementsFor(t, statement)
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
