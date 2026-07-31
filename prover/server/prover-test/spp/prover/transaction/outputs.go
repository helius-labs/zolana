package transaction

import (
	"fmt"
	"math/big"

	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

type outputWitnesses struct {
	outputs             []txcircuit.UtxoCircuitFields
	hashes              []*big.Int
	privateTxHashes     []*big.Int
	outputOwnerPkHashes []*big.Int
	outputNullifierPks  []*big.Int
	responses           []ProofUtxoResponse
}

type parsedUtxo struct {
	utxo             protocol.Utxo
	normalized       ProofUtxoRequest
	ownerKeyHash     *big.Int
	ownerNullifierPk *big.Int
	isP256           bool
}

func buildOutputWitnesses(shape protocol.Shape, requests []ProofUtxoRequest) (outputWitnesses, error) {
	outputs := outputWitnesses{
		outputs:             make([]txcircuit.UtxoCircuitFields, shape.NOutputs),
		hashes:              make([]*big.Int, shape.NOutputs),
		privateTxHashes:     make([]*big.Int, shape.NOutputs),
		outputOwnerPkHashes: make([]*big.Int, shape.NOutputs),
		outputNullifierPks:  make([]*big.Int, shape.NOutputs),
		responses:           make([]ProofUtxoResponse, 0, len(requests)),
	}
	for i, request := range requests {
		parsed, err := parseProofUtxo(request, nil)
		if err != nil {
			return outputWitnesses{}, fmt.Errorf("output %d: %w", i, err)
		}
		if parsed.utxo.Domain.Cmp(big.NewInt(protocol.UtxoDomain)) == 0 &&
			(parsed.ownerKeyHash == nil || parsed.ownerKeyHash.Sign() == 0) {
			return outputWitnesses{}, fmt.Errorf("output %d: owner public key and nullifier key are required", i)
		}
		outputHash, err := protocol.UtxoHash(parsed.utxo)
		if err != nil {
			return outputWitnesses{}, err
		}
		outputs.outputs[i] = toProofCircuitFields(parsed.utxo)
		outputs.hashes[i] = outputHash
		outputs.privateTxHashes[i] = outputHash
		outputs.outputOwnerPkHashes[i] = parsed.ownerKeyHash
		outputs.outputNullifierPks[i] = parsed.ownerNullifierPk
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
		outputs.outputs[i] = dummyUtxoFields(blinding)
		outputs.hashes[i] = hash
		outputs.privateTxHashes[i] = big.NewInt(0)
		outputs.outputNullifierPks[i] = big.NewInt(0)
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
	ringDataHash, err := parse.OptionalField(input.RingDataHash)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("ring_data_hash: %w", err)
	}
	ringProgramID, err := parse.OptionalField(input.RingProgramID)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("ring_program_id: %w", err)
	}
	// Default transact handles only bare UTXOs: the circuit pins these fields to
	// zero on every real input and output, so a non-zero value could never
	// prove. Reject early instead of failing inside the constraint solver.
	if dataHash.Sign() != 0 {
		return parsedUtxo{}, fmt.Errorf("data_hash must be zero: default transact handles only bare UTXOs")
	}
	if ringDataHash.Sign() != 0 {
		return parsedUtxo{}, fmt.Errorf("ring_data_hash must be zero: default transact handles only bare UTXOs")
	}
	if ringProgramID.Sign() != 0 {
		return parsedUtxo{}, fmt.Errorf("ring_program_id must be zero: default transact handles only bare UTXOs")
	}
	utxo := protocol.Utxo{
		Domain:        domain,
		Owner:         own.owner,
		Asset:         asset,
		Amount:        amount,
		Blinding:      blinding,
		DataHash:      dataHash,
		RingDataHash:  ringDataHash,
		RingProgramID: ringProgramID,
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
		RingDataHash:      proofFieldInput(ringDataHash),
		RingProgramID:     proofFieldInput(ringProgramID),
	}
	return parsedUtxo{
		utxo:             utxo,
		normalized:       normalized,
		ownerKeyHash:     own.keyHash,
		ownerNullifierPk: own.nullifierPk,
		isP256:           own.isP256,
	}, nil
}
