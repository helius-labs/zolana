package policy

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	spp "zolana/prover/circuits/spp_transaction/custom"
	"zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
)

func TestWindowedPolicyAllowsDummyInputs(t *testing.T) {
	for count := 2; count <= NInputs; count++ {
		t.Run(fmt.Sprintf("%d inputs", count), func(t *testing.T) {
			f := velocityDefault()
			f.rulesFree = true
			s := newStatement(t, f)
			record := s.inputs[len(s.inputs)-1]
			s.inputs = s.inputs[:1]
			for len(s.inputs) < count-1 {
				s.inputs = append(s.inputs, dummyOpening(t, int64(90+len(s.inputs))))
			}
			s.inputs = append(s.inputs, record)
			s.addressChain = spptest.MustHashChain4(t, spptest.RepeatBigInt(big.NewInt(0), count))
			if err := test.IsSolved(&CustomRingPolicyCircuit{}, s.assignment(t, nil), ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPolicyWithoutWindowAllowsAddressClaims(t *testing.T) {
	f := defaultFixture()
	f.rulesFree = true
	s := newStatement(t, f)
	s.addressChain = spptest.MustHashChain4(t, []*big.Int{big.NewInt(0), big.NewInt(0x1234)})
	if err := test.IsSolved(&CustomRingPolicyCircuit{}, s.assignment(t, nil), ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

func TestWindowedPolicyRejectsNamespaceAddressClaim(t *testing.T) {
	f := velocityDefault()
	f.rulesFree = true
	s := newStatement(t, f)
	zero := big.NewInt(0)
	record := s.inputs[len(s.inputs)-1]
	claim := UtxoWires{
		Domain: big.NewInt(protocol.AddressDomain), TreeID: big.NewInt(entriesTreeID),
		OwnerPkHash: record.OwnerPkHash, NullifierPk: record.NullifierPk,
		Asset: zero, Amount: zero, DataHash: zero, RingDataHash: zero, RingProgramID: zero,
		Blinding: spptest.MustPoseidon(t, 3, []*big.Int{SpendAddressDomain, big.NewInt(0xdead)}),
	}
	s.inputs = []UtxoWires{s.inputs[0], claim, record}
	s.outputs = []UtxoWires{s.outputs[0], s.outputs[len(s.outputs)-1]}
	s.inputs[0].RingProgramID, s.outputs[0].RingProgramID = s.ringID, s.ringID
	for i := range s.inputs {
		s.inputs[i].TreeID = big.NewInt(entriesTreeID)
	}
	for i := range s.outputs {
		s.outputs[i].TreeID = big.NewInt(entriesTreeID)
	}

	shape := shared.Shape{NInputs: len(s.inputs), NOutputs: len(s.outputs)}
	assignment, err := spp.NewCustomRingEddsaOnlyCircuit(shape)
	if err != nil {
		t.Fatal(err)
	}
	nullifiers := make([]*big.Int, len(s.inputs))
	secrets := []*big.Int{big.NewInt(7), zero, zero}
	leaves := map[uint64]*big.Int{}
	for i, input := range s.inputs {
		hash := hostUtxoHash(t, input)
		nullifiers[i] = spptest.MustNullifier(t, hash, spptest.AsBigInt(input.Blinding), secrets[i])
		if i != 1 {
			leaves[uint64(i)] = hash
		}
	}
	root, statePaths := spptest.MustBuildSparseStateTree(t, leaves)
	tree := spptest.MustNewNullifierTree(t)
	if err := tree.Insert(s.record.address); err != nil {
		t.Fatal(err)
	}
	for i, input := range s.inputs {
		path := statePaths[uint64(i)]
		if i == 1 {
			path = statePaths[0]
		}
		nonInclusion := spptest.MustNonInclusion(t, tree, nullifiers[i])
		assignment.Private.Inputs[i] = shared.Input{
			Utxo: sppOpening(t, input), StatePathIndex: path.PathIndex,
			StatePathElements: spptest.ToVariables(path.PathElements), TreeSlot: zero,
			NullifierLowValue: nonInclusion.LowValue, NullifierNextValue: nonInclusion.NextValue,
			NullifierLowPathIndex:    nonInclusion.LowIndex,
			NullifierLowPathElements: spptest.ToVariables(nonInclusion.PathElements),
			NullifierSecret:          secrets[i],
		}
		assignment.Private.InputOwnerPkHashes[i] = input.OwnerPkHash
		assignment.Public.Nullifiers[i] = nullifiers[i]
	}
	seed := big.NewInt(0x5151)
	outputSeed, err := protocol.OutputBlindingSeed(nullifiers[0], seed)
	if err != nil {
		t.Fatal(err)
	}
	outputs := make([]*big.Int, len(s.outputs))
	owners := []*big.Int{zero, spptest.AsBigInt(record.OwnerPkHash)}
	for i := range s.outputs {
		blinding, err := protocol.OutputBlinding(nullifiers[0], outputSeed, i)
		if err != nil {
			t.Fatal(err)
		}
		s.outputs[i].Blinding = blinding
		outputs[i] = hostUtxoHash(t, s.outputs[i])
		assignment.Private.Outputs[i] = sppOpening(t, s.outputs[i])
		assignment.Private.OutputOwnerPkHashes[i] = s.outputs[i].OwnerPkHash
		assignment.Private.OutputNullifierPks[i] = s.outputs[i].NullifierPk
		assignment.Public.OutputHashes[i] = outputs[i]
		assignment.Public.PublishedOutputOwnerPkHashes[i] = owners[i]
	}
	s.privateTxBlinding, err = protocol.PrivateTxBlinding(nullifiers[0], seed)
	if err != nil {
		t.Fatal(err)
	}
	s.addressChain = spptest.MustHashChain4(t, []*big.Int{zero, nullifiers[1], zero})
	s.stateRoot, s.nullifierRoot = root, tree.Root()
	s.updateHashes(t)
	treeSlots, err := protocol.PadTreeSlots(protocol.TreeSlot{ID: big.NewInt(entriesTreeID), UtxoRoot: root, NullifierRoot: tree.Root()})
	if err != nil {
		t.Fatal(err)
	}
	for i, slot := range treeSlots {
		assignment.Public.TreeSlots[i] = shared.TreeSlot{ID: slot.ID, UtxoRoot: slot.UtxoRoot, NullifierRoot: slot.NullifierRoot}
	}
	signers := make([]*big.Int, shape.SignerWidth())
	for i := range signers {
		signers[i] = zero
	}
	signers[0], signers[1] = spptest.AsBigInt(s.inputs[0].OwnerPkHash), spptest.AsBigInt(record.OwnerPkHash)
	assignment.Public.SignerPkHashes = spptest.ToVariables(signers)
	assignment.Public.OutputTreeID, assignment.Public.PrivateTxHash = big.NewInt(entriesTreeID), s.privateTxHash
	assignment.Public.ExternalDataHash, assignment.Public.RingProgramID = s.externalDataHash, s.ringID
	assignment.Public.InputFlags, assignment.Private.BlindingSeed = 1, seed
	for i := range assignment.Public.PublicAssets {
		assignment.Public.PublicAssets[i], assignment.Public.PublicAmounts[i] = zero, zero
	}
	assignment.Public.PublicInputHash, err = protocol.PublicInputHash(protocol.PublicInputs{
		Nullifiers: nullifiers, OutputUtxoHashes: outputs, TreeSlots: treeSlots,
		OutputTreeID: big.NewInt(entriesTreeID), PrivateTxHash: s.privateTxHash,
		ExternalDataHash: s.externalDataHash, RingProgramID: s.ringID,
		PublicAssets:   [protocol.NPublicSlots]*big.Int{zero, zero, zero},
		PublicAmounts:  [protocol.NPublicSlots]*big.Int{zero, zero, zero},
		SignerPkHashes: signers, InputFlags: big.NewInt(1),
		BindOutputOwnerTags: true, OutputOwnerPkHashes: owners,
	})
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := spp.NewCustomRingEddsaOnlyCircuit(shape)
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("SPP address claim failed: %v", err)
	}

	// Address and dummy inputs both contribute zero to the SPP input chain.
	s.inputs[1] = dummyOpening(t, 0x8181)
	policy := s.assignment(t, nil)
	if spptest.AsBigInt(assignment.Public.PrivateTxHash).Cmp(spptest.AsBigInt(policy.PrivateTxHash)) != 0 {
		t.Fatal("SPP and policy transaction hashes differ")
	}
	member := spptest.AsBigInt(s.inputs[0].OwnerPkHash)
	successor := spptest.MustNullifier(t, outputs[1], spptest.AsBigInt(s.outputs[1].Blinding), zero)
	heads := spptest.NewHeadMap(t, HeadMapHeight)
	transition := heads.Transfer(t, heads.Register(t, member, nullifiers[2]).NewIndex, successor)
	policy.PublicInputHash = spptest.MustHashChain(t, append(s.keys.ChainElements(t, s.privateTxHash),
		s.policyHash, root, tree.Root(), big.NewInt(entriesTreeID), s.ringID, s.ownOwnerHash,
		new(big.Int).SetUint64(s.windowIndex), boolVar(s.approval), transition.OldRoot, transition.NewRoot,
	))
	compressed := &CompressedPolicyCircuit{
		Policy: *policy, HeadOldRoot: transition.OldRoot, HeadNewRoot: transition.NewRoot,
		HeadNext: transition.Leaf.Next, HeadIndex: transition.Index,
	}
	for i := range compressed.HeadProof {
		compressed.HeadProof[i] = transition.Proof[i]
	}
	if err := test.IsSolved(&CompressedPolicyCircuit{}, compressed, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("windowed policy authorizes a namespace address claim hidden as padding")
	}
}

func sppOpening(t *testing.T, w UtxoWires) shared.UtxoCircuitFields {
	return shared.UtxoCircuitFields{
		Domain: w.Domain, Owner: spptest.MustOwnerHash(t, spptest.AsBigInt(w.OwnerPkHash), spptest.AsBigInt(w.NullifierPk)),
		Asset: w.Asset, Amount: w.Amount, Blinding: w.Blinding, DataHash: w.DataHash,
		RingDataHash: w.RingDataHash, RingProgramID: w.RingProgramID,
	}
}
