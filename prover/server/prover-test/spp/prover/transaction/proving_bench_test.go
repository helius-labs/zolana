package transaction

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"zolana/prover/prover-test/spp/internal/p256key"
	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

func BenchmarkProveByShape(b *testing.B) {
	for _, rail := range []struct {
		name string
		p256 bool
	}{
		{name: "solana", p256: false},
		{name: "p256", p256: true},
	} {
		for _, shape := range protocol.SupportedShapes {
			b.Run(fmt.Sprintf("%s/inputs_%d_outputs_%d", rail.name, shape.NInputs, shape.NOutputs), func(b *testing.B) {
				benchmarkProveShape(b, shape, rail.p256)
			})
		}
	}
}

func benchmarkProveShape(b *testing.B, shape protocol.Shape, p256 bool) {
	tx, payerHash, err := benchmarkTransaction(shape, p256)
	if err != nil {
		b.Fatal(err)
	}
	if TransactionRequiresP256(tx) != p256 {
		b.Fatalf("benchmark transaction rail mismatch: requiresP256=%v, want %v", TransactionRequiresP256(tx), p256)
	}
	ps, err := Setup(shape, TransactionRequiresP256(tx))
	if err != nil {
		b.Fatal(err)
	}
	built, err := buildProofAssignment(shape, tx, payerHash, proofBuildOptions{})
	if err != nil {
		b.Fatal(err)
	}
	assignment := built.circuit

	b.ReportAllocs()
	b.ResetTimer()
	b.ReportMetric(float64(ps.ConstraintSystem.GetNbConstraints()), "constraints")
	for i := 0; i < b.N; i++ {
		if _, err := Prove(ps, assignment); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkTransaction(shape protocol.Shape, p256 bool) (ProofTransactionRequest, *big.Int, error) {
	var payerPubkey [32]byte
	for i := range payerPubkey {
		payerPubkey[i] = byte(i + 1)
	}
	payerHash := protocol.Sha256BEField(payerPubkey[:])

	var (
		ownerKeyHash *big.Int
		p256Priv     *ecdsa.PrivateKey
		p256Pubkey   []byte
		err          error
	)
	if p256 {
		p256Priv, err = p256key.PrivateKeyFromScalar(big.NewInt(11))
		if err != nil {
			return ProofTransactionRequest{}, nil, err
		}
		p256Pubkey = elliptic.MarshalCompressed(elliptic.P256(), p256Priv.PublicKey.X, p256Priv.PublicKey.Y)
		ownerKeyHash, err = protocol.OwnerPkField(p256Pubkey)
	} else {
		ownerKeyHash, err = protocol.SolanaPkField(payerPubkey)
	}
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
		PublicAmountMode:         0,
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
		if p256 {
			utxoRequest.OwnerP256Pubkey = parse.BytesHex(p256Pubkey)
		} else {
			utxoRequest.OwnerSolanaPubkey = parse.BytesHex(payerPubkey[:])
		}
		tx.Inputs = append(tx.Inputs, ProofInputRequest{
			Utxo:            utxoRequest,
			LeafIndex:       uint64(i),
			NullifierSecret: proofFieldInput(nullifierSecret),
		})
	}

	for i := 0; i < shape.NOutputs; i++ {
		tx.Outputs = append(tx.Outputs, ProofUtxoRequest{
			Domain:        proofFieldInput(big.NewInt(protocol.UtxoDomain)),
			Owner:         proofFieldInput(owner),
			Asset:         proofFieldInput(protocol.SolAsset()),
			Amount:        proofFieldInput(outputAmount),
			Blinding:      proofFieldInput(big.NewInt(int64(2000 + i))),
			DataHash:      proofFieldInput(big.NewInt(0)),
			ZoneDataHash:  proofFieldInput(big.NewInt(0)),
			ZoneProgramID: proofFieldInput(big.NewInt(0)),
		})
	}

	if p256 {
		// The P256 signature covers the transcript-derived message hash, so
		// build the assignment once without it to learn the hash, then attach
		// the signature for the real proving run.
		built, err := buildProofAssignment(shape, tx, payerHash, proofBuildOptions{AllowMissingP256Signature: true})
		if err != nil {
			return ProofTransactionRequest{}, nil, err
		}
		msg := built.p256MessageDigest
		r, s, err := ecdsa.Sign(rand.Reader, p256Priv, msg[:])
		if err != nil {
			return ProofTransactionRequest{}, nil, err
		}
		tx.P256OwnerPubkey = parse.BytesHex(p256Pubkey)
		tx.P256SignatureR = proofFieldInput(r)
		tx.P256SignatureS = proofFieldInput(s)
	}
	return tx, payerHash, nil
}
