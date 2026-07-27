package transaction

import (
	"fmt"
	"math/big"
	"testing"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

func BenchmarkProveByShape(b *testing.B) {
	for _, shape := range protocol.SupportedShapes {
		b.Run(fmt.Sprintf("inputs_%d_outputs_%d", shape.NInputs, shape.NOutputs), func(b *testing.B) {
			benchmarkProveShape(b, shape)
		})
	}
}

func benchmarkProveShape(b *testing.B, shape protocol.Shape) {
	tx, payerHash, err := benchmarkTransaction(shape)
	if err != nil {
		b.Fatal(err)
	}
	ps, err := Setup(shape)
	if err != nil {
		b.Fatal(err)
	}
	built, err := buildProofAssignment(shape, tx, payerHash, proofBuildOptions{})
	if err != nil {
		b.Fatal(err)
	}
	assignment := built.witness

	b.ReportAllocs()
	b.ResetTimer()
	b.ReportMetric(float64(ps.ConstraintSystem.GetNbConstraints()), "constraints")
	for i := 0; i < b.N; i++ {
		if _, err := Prove(ps, assignment); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkTransaction(shape protocol.Shape) (ProofTransactionRequest, *big.Int, error) {
	var payerPubkey [32]byte
	for i := range payerPubkey {
		payerPubkey[i] = byte(i + 1)
	}
	payerHash := protocol.Sha256BEField(payerPubkey[:])

	ownerKeyHash, err := protocol.SolanaPkField(payerPubkey)
	if err != nil {
		return ProofTransactionRequest{}, nil, err
	}
	nullifierSecret := big.NewInt(12345)
	nullifierPk, err := protocol.NullifierPk(nullifierSecret)
	if err != nil {
		return ProofTransactionRequest{}, nil, err
	}
	owner, err := protocol.OwnerHash(ownerKeyHash, nullifierPk)
	if err != nil {
		return ProofTransactionRequest{}, nil, err
	}

	tx := ProofTransactionRequest{
		Name:                     fmt.Sprintf("bench-%s", shape),
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
