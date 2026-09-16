package custom_ring

import (
	"crypto/ecdh"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/custom_ring/policy"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
	"zolana/prover/prover/common"
)

// Chain elements 2 to 8 of the public input hash, the audit block recomputed
// over the fixture scalars by the transfer package's host mirror.
var auditChainElements = [7]string{
	"0x000268737cf1d852483220d399b5321261d5e9e90d8214dc62b4f7e4d0fee955",
	"0x000000000000000000000000000000000000000000000000000000000000c5d5",
	"0x00039dc51b59006b13f143944d4e432db7c032241ceb3698a6cc0cdabadf29b7",
	"0x0000000000000000000000000000000000000000000000000000000000001dec",
	"0x00038bd43dcdaea72a1db879b1ca6faac09593fd17893d22eeef926b5c1c245a",
	"0x000000000000000000000000000000000000000000000000000000000000133c",
	"0x1384dccfd224d268a2028165de1523e911e276a676568086166a3b782afdbada",
}

func TestCustomRingProofVerifies(t *testing.T) {
	loadedSystem := loadRingSystem(t, common.CustomRingPolicyKeyFile)
	params := rulesFreeParams(t)
	proof, err := Prove(loadedSystem, params)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := params.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof.Proof, loadedSystem.VerifyingKey, witness); err != nil {
		t.Fatal(err)
	}
}

func TestAuditProofVerifies(t *testing.T) {
	ps := loadRingSystem(t, common.CustomRingBaseKeyFile)
	params := baseParams(t)
	proof, err := Prove(ps, params)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := params.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof.Proof, ps.VerifyingKey, witness); err != nil {
		t.Fatal(err)
	}
}

// baseParams builds the audit statement over the same fixture scalars as
// auditChainElements, the private_tx_hash a pass-through.
func baseParams(t *testing.T) *BaseParameters {
	t.Helper()
	p := &BaseParameters{
		PrivateTxHash: big.NewInt(0xabcdef),
		TxViewingSk:   testScalar(0x11),
		EphSk:         testScalar(0x22),
	}
	auditorSk := testScalar(0x33)
	auditorKey, err := ecdh.P256().NewPrivateKey(auditorSk[:])
	if err != nil {
		t.Fatal(err)
	}
	copy(p.AuditorPk[:], auditorKey.PublicKey().Bytes())
	elements := []*big.Int{p.PrivateTxHash}
	for _, element := range auditChainElements {
		value, ok := new(big.Int).SetString(element[2:], 16)
		if !ok {
			t.Fatalf("bad element %s", element)
		}
		elements = append(elements, value)
	}
	p.PublicInputHash = spptest.MustHashChain(t, elements)
	return p
}

// rulesFreeParams opens a one input one output transfer against a length zero
// rule table with every list fact slot disabled.
func rulesFreeParams(t *testing.T) *PolicyParameters {
	t.Helper()
	p := &PolicyParameters{
		NIn:                1,
		NOut:               1,
		AddressChain:       big.NewInt(0x77),
		ExternalDataHash:   big.NewInt(0x5eed),
		PrivateTxBlinding:  big.NewInt(0x5b1d),
		StateRoot:          big.NewInt(0x0d),
		NullifierRoot:      big.NewInt(0x0e),
		EntriesTreeID:      big.NewInt(0x0f),
		RingID:             big.NewInt(0x5a),
		NamespaceOwnerHash: big.NewInt(0x99),
		Record:             zeroedRecord(),
	}
	for i := range p.Sources {
		p.Sources[i] = SourceOwner{ListId: 0, OwnerHash: big.NewInt(0)}
	}
	for i := range p.Velocity {
		p.Velocity[i] = VelocityRow{Asset: big.NewInt(0), Cap: big.NewInt(0), CosignAbove: big.NewInt(0)}
	}
	p.TxViewingSk = testScalar(0x11)
	p.EphSk = testScalar(0x22)
	auditorSk := testScalar(0x33)
	auditorKey, err := ecdh.P256().NewPrivateKey(auditorSk[:])
	if err != nil {
		t.Fatal(err)
	}
	copy(p.AuditorPk[:], auditorKey.PublicKey().Bytes())

	for i := range p.Inputs {
		p.Inputs[i] = zeroedOpening()
	}
	for i := range p.Outputs {
		p.Outputs[i] = zeroedOpening()
	}
	p.Inputs[0] = Opening{
		Domain:        big.NewInt(protocol.UtxoDomain),
		TreeID:        big.NewInt(0),
		OwnerPkHash:   big.NewInt(0xb2),
		NullifierPk:   big.NewInt(0xb3),
		Asset:         big.NewInt(0xa5),
		Amount:        big.NewInt(1000),
		Blinding:      big.NewInt(0x51),
		DataHash:      big.NewInt(0),
		RingDataHash:  big.NewInt(0),
		RingProgramID: big.NewInt(0),
	}
	p.Outputs[0] = Opening{
		Domain:        big.NewInt(protocol.UtxoDomain),
		TreeID:        big.NewInt(0),
		OwnerPkHash:   big.NewInt(0xa1),
		NullifierPk:   big.NewInt(0xa2),
		Asset:         big.NewInt(0xa5),
		Amount:        big.NewInt(1000),
		Blinding:      big.NewInt(0x52),
		DataHash:      big.NewInt(0),
		RingDataHash:  big.NewInt(0),
		RingProgramID: big.NewInt(0),
	}
	for i := range p.InlineAssets {
		p.InlineAssets[i] = big.NewInt(0)
		p.InlineLimits[i] = big.NewInt(0)
	}
	for i := range p.ListFacts {
		p.ListFacts[i] = zeroedListFact()
	}
	bindRulesFreeStatement(t, p)
	return p
}

// The tail extends the chain past the program context.
func bindRulesFreeStatement(t *testing.T, p *PolicyParameters, tail ...*big.Int) {
	t.Helper()
	inputs, outputs := []*big.Int{}, []*big.Int{}
	for i := 0; i < int(p.NIn); i++ {
		inputs = append(inputs, openingHash(t, p.Inputs[i]))
	}
	for i := 0; i < int(p.NOut); i++ {
		outputs = append(outputs, openingHash(t, p.Outputs[i]))
	}
	p.PrivateTxHash = spptest.MustPoseidon(t, 6, []*big.Int{
		spptest.MustHashChain4(t, inputs), spptest.MustHashChain4(t, outputs),
		p.AddressChain, p.ExternalDataHash, p.PrivateTxBlinding,
	})
	// Mirrors ring_policy::packed_ascii of the policy table domain tag.
	tableDomain := new(big.Int).SetBytes([]byte("zolana:ring-policy:policy:v1"))
	preimage := []*big.Int{tableDomain, big.NewInt(policy.PolicyVersion)}
	for range p.Sources {
		preimage = append(preimage, big.NewInt(0), big.NewInt(0))
	}
	preimage = append(preimage, big.NewInt(0), big.NewInt(0), big.NewInt(int64(p.VelocityCount)), new(big.Int).SetUint64(p.WindowSlots))
	for i := 0; i < int(p.VelocityCount); i++ {
		row := p.Velocity[i]
		preimage = append(preimage, row.Asset, row.Cap, row.CosignAbove)
	}
	policyHash := spptest.MustHashChain(t, preimage)
	elements := []*big.Int{p.PrivateTxHash}
	for _, element := range auditChainElements {
		value, ok := new(big.Int).SetString(element[2:], 16)
		if !ok {
			t.Fatalf("bad element %s", element)
		}
		elements = append(elements, value)
	}
	elements = append(elements, policyHash, p.StateRoot, p.NullifierRoot, p.EntriesTreeID,
		p.RingID, p.NamespaceOwnerHash, new(big.Int).SetUint64(p.WindowIndex), big.NewInt(0))
	p.PublicInputHash = spptest.MustHashChain(t, append(elements, tail...))
}

func zeroedRecord() SpendRecord {
	record := SpendRecord{
		Commitment: big.NewInt(0),
		Salt:       big.NewInt(0),
		NextSalt:   big.NewInt(0),
	}
	for i := range record.Assets {
		record.Assets[i] = big.NewInt(0)
		record.Spent[i] = big.NewInt(0)
	}
	return record
}

func openingHash(t *testing.T, slot Opening) *big.Int {
	t.Helper()
	return spptest.MustUtxoHash(t, protocol.Utxo{
		Domain:        slot.Domain,
		Owner:         spptest.MustOwnerHash(t, slot.OwnerPkHash, slot.NullifierPk),
		Asset:         slot.Asset,
		Amount:        slot.Amount,
		Blinding:      slot.Blinding,
		DataHash:      slot.DataHash,
		RingDataHash:  slot.RingDataHash,
		RingProgramID: slot.RingProgramID,
	}, slot.TreeID)
}

func zeroedOpening() Opening {
	return Opening{
		Domain:        big.NewInt(0),
		TreeID:        big.NewInt(0),
		OwnerPkHash:   big.NewInt(0),
		NullifierPk:   big.NewInt(0),
		Asset:         big.NewInt(0),
		Amount:        big.NewInt(0),
		Blinding:      big.NewInt(0),
		DataHash:      big.NewInt(0),
		RingDataHash:  big.NewInt(0),
		RingProgramID: big.NewInt(0),
	}
}

// testScalar is a non zero P256 scalar below the group order.
func testScalar(seed byte) [scalarLen]byte {
	var out [scalarLen]byte
	for i := range out {
		out[i] = seed ^ byte(i)
	}
	out[0] = 0x01
	return out
}
