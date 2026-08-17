package transaction

import (
	"fmt"
	"math/big"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

// sampleTransactionRequest is a balanced single-owner SOL transaction that fills
// every slot of the shape: the starting point tests mutate into the case they
// exercise.
func sampleTransactionRequest(shape protocol.Shape) (ProofTransactionRequest, *big.Int, error) {
	var payerPubkey [32]byte
	for i := range payerPubkey {
		payerPubkey[i] = byte(i + 1)
	}
	ownerKeyHash, err := protocol.SolanaPkField(payerPubkey)
	if err != nil {
		return ProofTransactionRequest{}, nil, err
	}
	payerHash := new(big.Int).Set(ownerKeyHash)
	nullifierSecret := big.NewInt(12345)
	spendKey, err := protocol.NewSpendKey(nullifierSecret)
	if err != nil {
		return ProofTransactionRequest{}, nil, err
	}
	owner, err := protocol.OwnerHash(ownerKeyHash, spendKey.Public)
	if err != nil {
		return ProofTransactionRequest{}, nil, err
	}

	tx := ProofTransactionRequest{
		Name:                     fmt.Sprintf("sample-%s", shape),
		InstructionDiscriminator: 1,
		ExpiryUnixTs:             123,
		SenderViewTag:            proofFieldInput(big.NewInt(9)),
		EncryptedUtxos:           "00",
		DataHash:                 proofFieldInput(big.NewInt(0)),
		ZoneDataHash:             proofFieldInput(big.NewInt(0)),
	}

	inputAmount := big.NewInt(int64(shape.NOutputs * 10))
	outputAmount := big.NewInt(int64(shape.NInputs * 10))
	for i := 0; i < shape.NInputs; i++ {
		utxo := protocol.Utxo{
			Domain:        big.NewInt(protocol.UtxoDomain),
			Owner:         owner,
			Asset:         protocol.SolAsset(),
			Amount:        new(big.Int).Set(inputAmount),
			Blinding:      big.NewInt(int64(1000 + i)),
			DataHash:      big.NewInt(0),
			ZoneDataHash:  big.NewInt(0),
			ZoneProgramID: big.NewInt(0),
		}
		hash, err := protocol.UtxoHash(utxo)
		if err != nil {
			return ProofTransactionRequest{}, nil, err
		}
		tx.StateEntries = append(tx.StateEntries, ProofStateEntry{
			Index: uint64(i),
			Hash:  proofFieldInput(hash),
		})
		utxoRequest := ProofUtxoRequest{
			Domain:        proofFieldInput(utxo.Domain),
			Asset:         proofFieldInput(utxo.Asset),
			Amount:        proofFieldInput(utxo.Amount),
			Blinding:      proofFieldInput(utxo.Blinding),
			DataHash:      proofFieldInput(utxo.DataHash),
			ZoneDataHash:  proofFieldInput(utxo.ZoneDataHash),
			ZoneProgramID: proofFieldInput(utxo.ZoneProgramID),
		}
		utxoRequest.OwnerSolanaPubkey = parse.BytesHex(payerPubkey[:])
		tx.Inputs = append(tx.Inputs, ProofInputRequest{
			Utxo:            utxoRequest,
			LeafIndex:       uint64(i),
			NullifierSecret: proofFieldInput(nullifierSecret),
		})
	}

	for i := 0; i < shape.NOutputs; i++ {
		tx.Outputs = append(tx.Outputs, ProofUtxoRequest{
			Domain:               proofFieldInput(big.NewInt(protocol.UtxoDomain)),
			Owner:                proofFieldInput(owner),
			OwnerSolanaPubkey:    parse.BytesHex(payerPubkey[:]),
			OwnerNullifierSecret: proofFieldInput(nullifierSecret),
			Asset:                proofFieldInput(protocol.SolAsset()),
			Amount:               proofFieldInput(outputAmount),
			Blinding:             proofFieldInput(big.NewInt(int64(2000 + i))),
			DataHash:             proofFieldInput(big.NewInt(0)),
			ZoneDataHash:         proofFieldInput(big.NewInt(0)),
			ZoneProgramID:        proofFieldInput(big.NewInt(0)),
		})
	}

	return tx, payerHash, nil
}
