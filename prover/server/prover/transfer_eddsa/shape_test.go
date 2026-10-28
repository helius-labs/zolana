package transfereddsa

import (
	"encoding/json"
	"strings"
	"testing"

	txcircuit "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// A request without the new fields is the protocol shape, and encoding a
// protocol request adds none of them, so existing clients and fixtures are
// unchanged.
func TestProtocolRequestsCarryNoShapeDimensions(t *testing.T) {
	transfer := sampleTransferParams(RingVariant)
	anonymous := sampleAnonymousEddsaParams()
	for name, params := range map[string]json.Marshaler{"transfer": transfer, "anonymous": anonymous} {
		encoded, err := params.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"signerWidth", "nHiddenOwners", "additionalOwnerPublicKeys", "additionalOwnerSignatures", "inputHiddenOwners"} {
			if strings.Contains(string(encoded), `"`+key+`"`) {
				t.Fatalf("%s: protocol request encodes %q", name, key)
			}
		}
	}
	if shape := transfer.ProofShape(); !shape.IsProtocol() || shape.KeyFile() != "transfer_ring_2_2.key" {
		t.Fatalf("transfer: got %s", shape)
	}
	if shape := anonymous.ProofShape(); !shape.IsProtocol() {
		t.Fatalf("anonymous: got %s", shape)
	}
}

// A dimension equal to the protocol value names the protocol key, so a client
// that spells out the protocol width still reaches the committed key.
func TestExplicitProtocolDimensionsNameTheProtocolKey(t *testing.T) {
	transfer := sampleTransferParams(RingVariant)
	transfer.SignerWidth = uint32(txcircuit.ProtocolSignerWidth(int(transfer.NInputs)))
	if shape := transfer.ProofShape(); !shape.IsProtocol() {
		t.Fatalf("transfer: got %s", shape)
	}
	anonymous := sampleAnonymousEddsaParams()
	anonymous.NHiddenOwners = 1
	anonymous.SignerWidth = uint32(txcircuit.ProtocolSignerWidth(int(anonymous.NInputs)))
	if shape := anonymous.ProofShape(); !shape.IsProtocol() {
		t.Fatalf("anonymous: got %s", shape)
	}
}

func TestTransferSignerWidthRoundTripsAndSizesTheWitness(t *testing.T) {
	params := sampleTransferParams(RingVariant)
	params.SignerWidth = 1
	params.SignerPkHashes = countedFieldElements(1, 0x1212)
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	var decoded TransferParameters
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SignerWidth != 1 {
		t.Fatalf("signer width = %d", decoded.SignerWidth)
	}
	want := common.ProofShape{Circuit: common.TransferRingCircuitType, Inputs: 2, Outputs: 2, SignerWidth: 1}
	if decoded.ProofShape() != want {
		t.Fatalf("shape = %s", decoded.ProofShape())
	}
	if err := decoded.ValidateShape(); err != nil {
		t.Fatal(err)
	}
	if _, err := decoded.CreateWitness(); err != nil {
		t.Fatal(err)
	}
	decoded.SignerPkHashes = countedFieldElements(txcircuit.ProtocolSignerWidth(2), 0x1212)
	if _, err := decoded.CreateWitness(); err == nil || !strings.Contains(err.Error(), "signer pk hash count") {
		t.Fatalf("a protocol-width vector for a width-1 circuit: %v", err)
	}
}

func TestRingAuthorityRefusesASignerWidth(t *testing.T) {
	params := sampleTransferParams(RingAuthorityVariant)
	params.SignerWidth = uint32(txcircuit.ProtocolSignerWidth(2))
	if params.ProofShape().Supported() {
		t.Fatal("ring authority accepted a signer width")
	}
	assertShapeError(t, params, "unsupported transfer shape")
}

// twoOwnerAnonymousParams is the 1x1 sample widened to a 2x2 spend whose
// inputs belong to two hidden owners.
func twoOwnerAnonymousParams() *AnonymousEddsaTransferParameters {
	params := sampleAnonymousEddsaParams()
	second := sampleInputParams(1)
	params.NInputs = 2
	params.Inputs = append(params.Inputs, second)
	params.NOutputs = 2
	params.Outputs = append(params.Outputs, params.Outputs[0])
	params.PublishedOutputOwnerPkHashes = countedFieldElements(2, 0x1212)
	params.InputFlags = sampleInputFlags(params.Inputs)
	params.TreeSlots = sampleTreeSlots()
	params.SignerPkHashes = countedFieldElements(txcircuit.ProtocolSignerWidth(2), 0x1212)
	params.Cache = CacheSelectionParams{}
	params.NHiddenOwners = 2
	params.AdditionalOwnerPublicKeys = [][32]byte{{0x22}}
	params.AdditionalOwnerSignatures = [][64]byte{{0x33}}
	params.InputHiddenOwners = []uint32{0, 1}
	return params
}

func TestAnonymousHiddenOwnersRoundTrip(t *testing.T) {
	params := twoOwnerAnonymousParams()
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	var decoded AnonymousEddsaTransferParameters
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.NHiddenOwners != 2 ||
		len(decoded.AdditionalOwnerPublicKeys) != 1 || decoded.AdditionalOwnerPublicKeys[0] != params.AdditionalOwnerPublicKeys[0] ||
		len(decoded.AdditionalOwnerSignatures) != 1 || decoded.AdditionalOwnerSignatures[0] != params.AdditionalOwnerSignatures[0] ||
		len(decoded.InputHiddenOwners) != 2 || decoded.InputHiddenOwners[1] != 1 {
		t.Fatalf("decoded %+v", decoded)
	}
	want := common.ProofShape{Circuit: common.TransferAnonymousRingEddsaCircuitType, Inputs: 2, Outputs: 2, HiddenOwners: 2}
	if decoded.ProofShape() != want {
		t.Fatalf("shape = %s", decoded.ProofShape())
	}
}

func TestAnonymousHiddenOwnersRejectMalformedOwnerWires(t *testing.T) {
	for name, mutate := range map[string]func(*AnonymousEddsaTransferParameters){
		"missing key":          func(p *AnonymousEddsaTransferParameters) { p.AdditionalOwnerPublicKeys = nil },
		"missing signature":    func(p *AnonymousEddsaTransferParameters) { p.AdditionalOwnerSignatures = nil },
		"short indices":        func(p *AnonymousEddsaTransferParameters) { p.InputHiddenOwners = []uint32{0} },
		"out of range index":   func(p *AnonymousEddsaTransferParameters) { p.InputHiddenOwners = []uint32{0, 2} },
		"more owners than ins": func(p *AnonymousEddsaTransferParameters) { p.NHiddenOwners = 3 },
		"wires for one owner": func(p *AnonymousEddsaTransferParameters) {
			p.NHiddenOwners = 0
		},
	} {
		t.Run(name, func(t *testing.T) {
			params := twoOwnerAnonymousParams()
			mutate(params)
			if err := params.ValidateShape(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if err := twoOwnerAnonymousParams().ValidateShape(); err != nil {
		t.Fatalf("valid two-owner request rejected: %v", err)
	}
}

func TestAnonymousDecodeRejectsMalformedOwnerKeys(t *testing.T) {
	encoded, err := json.Marshal(twoOwnerAnonymousParams())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]any{
		"additionalOwnerPublicKeys": []string{"0x22"},
		"additionalOwnerSignatures": []string{"0xzz"},
	} {
		broken := cloneFields(fields)
		broken[key] = value
		assertAnonymousEddsaDecodeFails(t, broken)
	}
}

func TestSystemCheckComparesEveryDimension(t *testing.T) {
	system := &common.TransferProofSystem{
		CircuitType:  common.TransferAnonymousRingEddsaCircuitType,
		NInputs:      2,
		NOutputs:     2,
		HiddenOwners: 2,
	}
	if err := checkSystem(system, twoOwnerAnonymousParams().ProofShape()); err != nil {
		t.Fatal(err)
	}
	if err := checkSystem(system, sampleAnonymousEddsaParams().ProofShape()); err == nil {
		t.Fatal("a two-owner system accepted a protocol request")
	}
	protocol := twoOwnerAnonymousParams()
	protocol.NHiddenOwners = 0
	if err := checkSystem(system, protocol.ProofShape()); err == nil {
		t.Fatal("a two-owner system accepted a single-owner request")
	}
}
