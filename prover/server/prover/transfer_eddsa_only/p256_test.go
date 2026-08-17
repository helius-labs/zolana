package transfereddsaonly

import (
	"encoding/json"
	"math/big"
	"reflect"
	"testing"

	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"
)

// distinctFields hands out a fresh value per call so every parameter field
// carries a different number. A field dropped from the JSON encoding decodes
// back as zero, which only shows up when no two fields share a value.
type distinctFields struct{ next int64 }

func (d *distinctFields) fe() *big.Int {
	d.next++
	return big.NewInt(d.next)
}

func (d *distinctFields) slice(n int) []*big.Int {
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = d.fe()
	}
	return out
}

func (d *distinctFields) utxo() UtxoParams {
	return UtxoParams{
		Domain:        d.fe(),
		Owner:         d.fe(),
		Asset:         d.fe(),
		Amount:        d.fe(),
		Blinding:      d.fe(),
		DataHash:      d.fe(),
		ZoneDataHash:  d.fe(),
		ZoneProgramID: d.fe(),
	}
}

func p256RoundTripParams(d *distinctFields) P256TransferParameters {
	return P256TransferParameters{
		NInputs:  1,
		NOutputs: 1,
		Inputs: []InputParams{{
			Utxo:                     d.utxo(),
			IsDummy:                  d.fe(),
			StatePathElements:        d.slice(txcircuit.StateTreeHeight),
			StatePathIndex:           d.fe(),
			NullifierLowValue:        d.fe(),
			NullifierNextValue:       d.fe(),
			NullifierLowPathElements: d.slice(txcircuit.NullifierTreeHeight),
			NullifierLowPathIndex:    d.fe(),
			UtxoTreeRoot:             d.fe(),
			NullifierTreeRoot:        d.fe(),
			Nullifier:                d.fe(),
			OwnerPkHash:              d.fe(),
			NullifierSecret:          d.fe(),
			SpendPkX:                 d.fe(),
			SpendPkY:                 d.fe(),
			SpendSigX:                d.fe(),
			SpendSigY:                d.fe(),
			SpendSigS:                d.fe(),
		}},
		Outputs: []OutputParams{{
			Utxo:        d.utxo(),
			IsDummy:     d.fe(),
			Hash:        d.fe(),
			OwnerPkHash: d.fe(),
			SpendPkX:    d.fe(),
			SpendPkY:    d.fe(),
		}},
		ExternalDataHash:             d.fe(),
		PrivateTxHash:                d.fe(),
		P256PubX:                     d.fe(),
		P256PubY:                     d.fe(),
		P256SigR:                     d.fe(),
		P256SigS:                     d.fe(),
		P256MessageHashLow:           d.fe(),
		P256MessageHashHigh:          d.fe(),
		DefaultP256OwnerPkHash:       d.fe(),
		PublicAssets:                 d.slice(txcircuit.NPublicSlots),
		PublicAmounts:                d.slice(txcircuit.NPublicSlots),
		ZoneProgramID:                d.fe(),
		SignerPkHashes:               d.slice(2),
		AllowDummyInputs:             d.fe(),
		PublishedOutputOwnerPkHashes: d.slice(1),
		PublicInputHash:              d.fe(),
	}
}

// Every field must survive the round trip. Comparing the whole struct is what
// catches a field that the encoder forgets: feHex(nil) and feFromHex("") both
// produce zero, so a dropped field is invisible to any check that does not
// compare values.
func TestP256TransferParametersJSONRoundTrip(t *testing.T) {
	params := p256RoundTripParams(&distinctFields{})

	encoded, err := json.Marshal(&params)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if raw["circuitType"] != string(common.TransferP256ZoneCircuitType) {
		t.Fatalf("circuit type = %v", raw["circuitType"])
	}
	if _, exists := raw["p256SigningPkField"]; exists {
		t.Fatal("obsolete p256SigningPkField must not be serialized")
	}

	var decoded P256TransferParameters
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal params: %v", err)
	}
	if err := decoded.ValidateShape(); err != nil {
		t.Fatalf("validate shape: %v", err)
	}
	if !reflect.DeepEqual(params, decoded) {
		t.Fatalf("round trip lost or changed a field:\n got %+v\nwant %+v", decoded, params)
	}
}

// The same guarantee for the Solana-only rail, which carries the spend key and
// signature that the P256 rail shares.
func TestTransferParametersJSONRoundTrip(t *testing.T) {
	d := &distinctFields{}
	source := p256RoundTripParams(d)
	params := TransferParameters{
		NInputs:                      source.NInputs,
		NOutputs:                     source.NOutputs,
		Inputs:                       source.Inputs,
		Outputs:                      source.Outputs,
		ExternalDataHash:             source.ExternalDataHash,
		PrivateTxHash:                source.PrivateTxHash,
		PublicAssets:                 source.PublicAssets,
		PublicAmounts:                source.PublicAmounts,
		ZoneProgramID:                source.ZoneProgramID,
		SignerPkHashes:               source.SignerPkHashes,
		AllowDummyInputs:             source.AllowDummyInputs,
		PublishedOutputOwnerPkHashes: source.PublishedOutputOwnerPkHashes,
		Variant:                      ZoneVariant,
		PublicInputHash:              source.PublicInputHash,
	}

	encoded, err := json.Marshal(params.CreateTransferParametersJSON())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var reparsed TransferParametersJSON
	if err := json.Unmarshal(encoded, &reparsed); err != nil {
		t.Fatalf("unmarshal json struct: %v", err)
	}
	var decoded TransferParameters
	if err := decoded.UpdateWithJSON(reparsed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// UpdateWithJSON does not carry the variant; it comes from the circuit type.
	decoded.Variant = params.Variant
	if !reflect.DeepEqual(params, decoded) {
		t.Fatalf("round trip lost or changed a field:\n got %+v\nwant %+v", decoded, params)
	}
}
