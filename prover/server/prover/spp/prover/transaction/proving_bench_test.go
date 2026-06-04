package transaction

import (
	"fmt"
	"math/big"
	"testing"

	"light/light-prover/prover/spp/model"
	"light/light-prover/prover/spp/parse"
)

func BenchmarkProveByShape(b *testing.B) {
	shapes := []model.Shape{
		{NInputs: 1, NOutputs: 2},
		{NInputs: 2, NOutputs: 2},
		{NInputs: 3, NOutputs: 3},
		{NInputs: 5, NOutputs: 3},
		{NInputs: 1, NOutputs: 8},
	}
	for _, shape := range shapes {
		shape := shape
		b.Run(fmt.Sprintf("inputs_%d_outputs_%d", shape.NInputs, shape.NOutputs), func(b *testing.B) {
			benchmarkProveShape(b, shape)
		})
	}
}

func benchmarkProveShape(b *testing.B, shape model.Shape) {
	ps, err := Setup(shape)
	if err != nil {
		b.Fatal(err)
	}
	tx, signerHash, err := benchmarkTransaction(shape)
	if err != nil {
		b.Fatal(err)
	}
	assignment, _, _, _, err := buildProofAssignment(shape, tx, signerHash, proofBuildOptions{})
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.ReportMetric(float64(ps.ConstraintSystem.GetNbConstraints()), "constraints")
	for i := 0; i < b.N; i++ {
		if _, err := Prove(ps, assignment); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkTransaction(shape model.Shape) (ProofTransactionRequest, *big.Int, error) {
	var signerPubkey [32]byte
	for i := range signerPubkey {
		signerPubkey[i] = byte(i + 1)
	}
	signerHash := model.HashToFieldSize(signerPubkey[:])
	ownerKeyHash, err := model.SolanaPkHash(signerPubkey)
	if err != nil {
		return ProofTransactionRequest{}, nil, err
	}
	nullifierSecret := big.NewInt(12345)
	nullifierPk, err := model.NullifierPk(nullifierSecret)
	if err != nil {
		return ProofTransactionRequest{}, nil, err
	}
	owner, err := model.OwnerHash(ownerKeyHash, nullifierPk)
	if err != nil {
		return ProofTransactionRequest{}, nil, err
	}

	tx := ProofTransactionRequest{
		Name:                     fmt.Sprintf("bench-%s", shape),
		InstructionDiscriminator: 1,
		ExpiryUnixTs:             123,
		SenderViewTag:            proofFieldInput(big.NewInt(9)),
		PublicAmountMode:         0,
		EncryptedUtxos:           "00",
		ProgramIDHashchain:       proofFieldInput(big.NewInt(0)),
		DataHash:                 proofFieldInput(big.NewInt(0)),
		ZoneDataHash:             proofFieldInput(big.NewInt(0)),
	}

	inputAmount := big.NewInt(int64(shape.NOutputs * 10))
	outputAmount := big.NewInt(int64(shape.NInputs * 10))
	for i := 0; i < shape.NInputs; i++ {
		utxo := model.Utxo{
			Domain:        big.NewInt(int64(i + 1)),
			Owner:         owner,
			AssetID:       big.NewInt(model.SpecSolAssetID),
			AssetAmount:   new(big.Int).Set(inputAmount),
			Blinding:      big.NewInt(int64(1000 + i)),
			DataHash:      big.NewInt(0),
			ZoneDataHash:  big.NewInt(0),
			ZoneProgramID: big.NewInt(0),
		}
		hash, err := model.UtxoHash(utxo)
		if err != nil {
			return ProofTransactionRequest{}, nil, err
		}
		tx.StateEntries = append(tx.StateEntries, ProofStateEntry{
			Index: uint64(i),
			Hash:  proofFieldInput(hash),
		})
		tx.Inputs = append(tx.Inputs, ProofInputRequest{
			Utxo: ProofUtxoRequest{
				Domain:            proofFieldInput(utxo.Domain),
				OwnerSolanaPubkey: parse.BytesHex(signerPubkey[:]),
				AssetID:           proofFieldInput(utxo.AssetID),
				AssetAmount:       proofFieldInput(utxo.AssetAmount),
				Blinding:          proofFieldInput(utxo.Blinding),
				DataHash:          proofFieldInput(utxo.DataHash),
				ZoneDataHash:      proofFieldInput(utxo.ZoneDataHash),
				ZoneProgramID:     proofFieldInput(utxo.ZoneProgramID),
			},
			LeafIndex:       uint64(i),
			NullifierSecret: proofFieldInput(nullifierSecret),
		})
	}

	for i := 0; i < shape.NOutputs; i++ {
		tx.Outputs = append(tx.Outputs, ProofUtxoRequest{
			Domain:        proofFieldInput(big.NewInt(int64(100 + i))),
			Owner:         proofFieldInput(owner),
			AssetID:       proofFieldInput(big.NewInt(model.SpecSolAssetID)),
			AssetAmount:   proofFieldInput(outputAmount),
			Blinding:      proofFieldInput(big.NewInt(int64(2000 + i))),
			DataHash:      proofFieldInput(big.NewInt(0)),
			ZoneDataHash:  proofFieldInput(big.NewInt(0)),
			ZoneProgramID: proofFieldInput(big.NewInt(0)),
		})
	}
	return tx, signerHash, nil
}
