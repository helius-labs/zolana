package custom_ring

import (
	"crypto/ecdh"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/custom_ring/transfer"
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
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	keyPath := filepath.Join(filepath.Dir(source), "..", "..", "proving-keys", common.CustomRingKeyFile)
	if _, err := os.Stat(keyPath); err != nil {
		t.Skip("custom ring proving key is not available")
	}
	loaded, err := common.ReadSystemFromFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	loadedSystem, ok := loaded.(*common.RingProofSystem)
	if !ok {
		t.Fatalf("unexpected proof system %T", loaded)
	}
	params := rulesFreeParams(t)
	proof, err := ProveCustomRing(loadedSystem, params)
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

// rulesFreeParams opens a one input one output transfer against a length zero
// rule table with every pool slot disabled.
func rulesFreeParams(t *testing.T) *CustomRingParameters {
	t.Helper()
	p := &CustomRingParameters{
		NIn:              1,
		NOut:             1,
		AddressChain:     big.NewInt(0x77),
		ExternalDataHash: big.NewInt(0x5eed),
		RecordsOwnerHash: big.NewInt(0x0c),
		StateRoot:        big.NewInt(0x0d),
		NullifierRoot:    big.NewInt(0x0e),
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
	}
	for i := range p.Pool {
		p.Pool[i] = zeroedPoolEntry()
	}

	p.PrivateTxHash = spptest.MustPoseidon(t, 5, []*big.Int{
		openingHash(t, p.Inputs[0]),
		openingHash(t, p.Outputs[0]),
		p.AddressChain,
		p.ExternalDataHash,
	})
	// Mirrors ring_policy::packed_ascii of the policy table domain tag.
	tableDomain := new(big.Int).SetBytes([]byte("zolana:ring-policy:policy:v1"))
	policyHash := spptest.MustHashChain(t, []*big.Int{
		tableDomain,
		big.NewInt(transfer.PolicyVersion),
		p.RecordsOwnerHash,
		big.NewInt(0),
	})
	elements := []*big.Int{p.PrivateTxHash}
	for _, element := range auditChainElements {
		value, ok := new(big.Int).SetString(element[2:], 16)
		if !ok {
			t.Fatalf("bad element %s", element)
		}
		elements = append(elements, value)
	}
	p.PublicInputHash = spptest.MustHashChain(t, append(elements,
		policyHash, p.StateRoot, p.NullifierRoot))
	return p
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
	})
}

func zeroedOpening() Opening {
	return Opening{
		Domain:        big.NewInt(0),
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
