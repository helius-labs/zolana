package transaction

import (
	"fmt"
	"math/big"

	txcircuit "light/light-prover/prover/spp/circuit/transaction"
	"light/light-prover/prover/spp/model"
	"light/light-prover/prover/spp/parse"
)

type outputWitnesses struct {
	outputs   []txcircuit.Output
	hashes    []*big.Int
	responses []ProofUtxoResponse
}

type parsedUtxo struct {
	utxo         model.Utxo
	normalized   ProofUtxoRequest
	ownerKeyHash *big.Int
	isP256       bool
}

func buildOutputWitnesses(shape model.Shape, requests []ProofUtxoRequest) (outputWitnesses, error) {
	outputs := outputWitnesses{
		outputs:   make([]txcircuit.Output, shape.NOutputs),
		hashes:    make([]*big.Int, shape.NOutputs),
		responses: make([]ProofUtxoResponse, 0, len(requests)),
	}
	for i, request := range requests {
		parsed, err := parseProofUtxo(request, nil)
		if err != nil {
			return outputWitnesses{}, fmt.Errorf("output %d: %w", i, err)
		}
		outputHash, err := model.UtxoHash(parsed.utxo)
		if err != nil {
			return outputWitnesses{}, err
		}
		outputs.outputs[i] = txcircuit.Output{
			Utxo: toProofCircuitFields(parsed.utxo),
			Hash: outputHash,
		}
		outputs.hashes[i] = outputHash
		outputs.responses = append(outputs.responses, ProofUtxoResponse{
			Utxo: parsed.normalized,
			Hash: parse.FieldHex(outputHash),
		})
	}
	return outputs, nil
}

func parseProofUtxo(input ProofUtxoRequest, inputNullifierSecret *big.Int) (parsedUtxo, error) {
	domain, err := parse.Field(input.Domain)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("domain: %w", err)
	}
	own, err := parseOwner(input, inputNullifierSecret)
	if err != nil {
		return parsedUtxo{}, err
	}
	assetID, err := parse.Field(input.AssetID)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("asset_id: %w", err)
	}
	assetAmount, err := parse.Field(input.AssetAmount)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("asset_amount: %w", err)
	}
	blinding, err := parse.Field(input.Blinding)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("blinding: %w", err)
	}
	dataHash, err := parse.OptionalField(input.DataHash)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("data_hash: %w", err)
	}
	zoneDataHash, err := parse.OptionalField(input.ZoneDataHash)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("zone_data_hash: %w", err)
	}
	zoneProgramID, err := parse.OptionalField(input.ZoneProgramID)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("zone_program_id: %w", err)
	}
	utxo := model.Utxo{
		Domain:        domain,
		Owner:         own.owner,
		AssetID:       assetID,
		AssetAmount:   assetAmount,
		Blinding:      blinding,
		DataHash:      dataHash,
		ZoneDataHash:  zoneDataHash,
		ZoneProgramID: zoneProgramID,
	}
	normalized := ProofUtxoRequest{
		Domain:            proofFieldInput(domain),
		Owner:             proofFieldInput(own.owner),
		OwnerSolanaPubkey: parse.HexString(input.OwnerSolanaPubkey),
		OwnerP256Pubkey:   parse.HexString(input.OwnerP256Pubkey),
		AssetID:           proofFieldInput(assetID),
		AssetAmount:       proofFieldInput(assetAmount),
		Blinding:          proofFieldInput(blinding),
		DataHash:          proofFieldInput(dataHash),
		ZoneDataHash:      proofFieldInput(zoneDataHash),
		ZoneProgramID:     proofFieldInput(zoneProgramID),
	}
	return parsedUtxo{
		utxo:         utxo,
		normalized:   normalized,
		ownerKeyHash: own.keyHash,
		isP256:       own.isP256,
	}, nil
}
