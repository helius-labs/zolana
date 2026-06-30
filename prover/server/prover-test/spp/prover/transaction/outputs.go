package transaction

import (
	"fmt"
	"math/big"

	txcircuit "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

type outputWitnesses struct {
	outputs         []txcircuit.Output
	hashes          []*big.Int
	privateTxHashes []*big.Int
	responses       []ProofUtxoResponse
}

type parsedUtxo struct {
	utxo         protocol.Utxo
	normalized   ProofUtxoRequest
	ownerKeyHash *big.Int
	isP256       bool
}

func buildOutputWitnesses(shape protocol.Shape, requests []ProofUtxoRequest) (outputWitnesses, error) {
	outputs := outputWitnesses{
		outputs:         make([]txcircuit.Output, shape.NOutputs),
		hashes:          make([]*big.Int, shape.NOutputs),
		privateTxHashes: make([]*big.Int, shape.NOutputs),
		responses:       make([]ProofUtxoResponse, 0, len(requests)),
	}
	for i, request := range requests {
		parsed, err := parseProofUtxo(request, nil)
		if err != nil {
			return outputWitnesses{}, fmt.Errorf("output %d: %w", i, err)
		}
		outputHash, err := protocol.UtxoHash(parsed.utxo)
		if err != nil {
			return outputWitnesses{}, err
		}
		outputs.outputs[i] = txcircuit.Output{
			Utxo:        toProofCircuitFields(parsed.utxo),
			IsDummy:     big.NewInt(0),
			Hash:        outputHash,
			OwnerPkHash: big.NewInt(0),
			NullifierPk: big.NewInt(0),
		}
		outputs.hashes[i] = outputHash
		outputs.privateTxHashes[i] = outputHash
		outputs.responses = append(outputs.responses, ProofUtxoResponse{
			Utxo: parsed.normalized,
			Hash: parse.FieldHex(outputHash),
		})
	}

	for i := len(requests); i < shape.NOutputs; i++ {
		blinding, err := randomBlinding()
		if err != nil {
			return outputWitnesses{}, fmt.Errorf("dummy output %d blinding: %w", i, err)
		}
		utxo := dummyUtxo(blinding)
		hash, err := protocol.UtxoHash(utxo)
		if err != nil {
			return outputWitnesses{}, fmt.Errorf("dummy output %d hash: %w", i, err)
		}
		outputs.outputs[i] = txcircuit.Output{
			Utxo:        dummyUtxoFields(blinding),
			IsDummy:     big.NewInt(1),
			Hash:        hash,
			OwnerPkHash: big.NewInt(0),
			NullifierPk: big.NewInt(0),
		}
		outputs.hashes[i] = hash
		outputs.privateTxHashes[i] = big.NewInt(0)
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
	asset, err := parse.Field(input.Asset)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("asset_id: %w", err)
	}
	amount, err := parse.Field(input.Amount)
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
	// Default transact handles only bare UTXOs: the circuit pins these fields to
	// zero on every real input and output, so a non-zero value could never
	// prove. Reject early instead of failing inside the constraint solver.
	if dataHash.Sign() != 0 {
		return parsedUtxo{}, fmt.Errorf("data_hash must be zero: default transact handles only bare UTXOs")
	}
	if zoneDataHash.Sign() != 0 {
		return parsedUtxo{}, fmt.Errorf("zone_data_hash must be zero: default transact handles only bare UTXOs")
	}
	if zoneProgramID.Sign() != 0 {
		return parsedUtxo{}, fmt.Errorf("zone_program_id must be zero: default transact handles only bare UTXOs")
	}
	utxo := protocol.Utxo{
		Domain:        domain,
		Owner:         own.owner,
		Asset:         asset,
		Amount:        amount,
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
		Asset:             proofFieldInput(asset),
		Amount:            proofFieldInput(amount),
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
