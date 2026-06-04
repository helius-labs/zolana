package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"light/light-prover/prover/spp/internal/p256key"
	"light/light-prover/prover/spp/model"
	"light/light-prover/prover/spp/parse"
	txprover "light/light-prover/prover/spp/prover/transaction"
)

func TestBuildProofSigningPayloadAllowsUnsignedP256Input(t *testing.T) {
	request, _, _ := p256ProofRequest(t)

	payload, err := txprover.BuildProofSigningPayload(&txprover.ProofSystem{Shape: model.Shape{NInputs: 1, NOutputs: 2}}, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.Transactions) != 1 {
		t.Fatalf("payload transaction count = %d, want 1", len(payload.Transactions))
	}
	if !payload.Transactions[0].RequiresP256Signature {
		t.Fatal("signing payload did not request a P256 signature")
	}
	if payload.Transactions[0].PrivateTxHash == parse.FieldHex(big.NewInt(0)) {
		t.Fatal("private tx hash was zero")
	}

	if _, err := txprover.BuildProofBundle(&txprover.ProofSystem{Shape: model.Shape{NInputs: 1, NOutputs: 2}}, request); err == nil {
		t.Fatal("unsigned P256 proof bundle unexpectedly succeeded")
	}
}

func TestBuildProofBundleAcceptsSignedP256Input(t *testing.T) {
	request, priv, p256Pubkey := p256ProofRequest(t)
	payload, err := txprover.BuildProofSigningPayload(&txprover.ProofSystem{Shape: model.Shape{NInputs: 1, NOutputs: 2}}, request)
	if err != nil {
		t.Fatal(err)
	}
	privateTxHash, err := parse.Field("0x" + payload.Transactions[0].PrivateTxHash)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := parse.FieldBytes(privateTxHash)
	if err != nil {
		t.Fatal(err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, msg[:])
	if err != nil {
		t.Fatal(err)
	}

	tx := &request.Transactions[0]
	tx.P256OwnerPubkey = parse.BytesHex(p256Pubkey)
	tx.P256SignatureR = fieldInput(r)
	tx.P256SignatureS = fieldInput(s)

	ps, err := txprover.Setup(model.Shape{NInputs: 1, NOutputs: 2})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := txprover.BuildProofBundle(ps, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Transactions) != 1 {
		t.Fatalf("bundle transaction count = %d, want 1", len(bundle.Transactions))
	}
	if bundle.Transactions[0].PrivateTxHash != payload.Transactions[0].PrivateTxHash {
		t.Fatalf("private tx hash = %q, want %q", bundle.Transactions[0].PrivateTxHash, payload.Transactions[0].PrivateTxHash)
	}
	if bundle.Transactions[0].Proof == nil {
		t.Fatal("proof is nil")
	}
}

func p256ProofRequest(t *testing.T) (txprover.ProofBundleRequest, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := p256key.PrivateKeyFromScalar(big.NewInt(11))
	if err != nil {
		t.Fatal(err)
	}
	p256Pubkey := elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	nullifierSecret := big.NewInt(19)
	ownerKeyHash, err := model.P256OwnerKeyHash(p256Pubkey)
	if err != nil {
		t.Fatal(err)
	}
	nullifierPk, err := model.NullifierPk(nullifierSecret)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := model.OwnerHash(ownerKeyHash, nullifierPk)
	if err != nil {
		t.Fatal(err)
	}
	utxo := model.Utxo{
		Domain:        big.NewInt(7),
		Owner:         owner,
		AssetID:       big.NewInt(1),
		AssetAmount:   big.NewInt(5),
		Blinding:      big.NewInt(23),
		DataHash:      big.NewInt(0),
		ZoneDataHash:  big.NewInt(0),
		ZoneProgramID: big.NewInt(0),
	}
	utxoHash, err := model.UtxoHash(utxo)
	if err != nil {
		t.Fatal(err)
	}

	return txprover.ProofBundleRequest{
		SolanaSignerPubkey: parse.BytesHex(make([]byte, 32)),
		Transactions: []txprover.ProofTransactionRequest{{
			Name:                     "unsigned-p256",
			InstructionDiscriminator: 1,
			ExpiryUnixTs:             123,
			SenderViewTag:            fieldInput(big.NewInt(9)),
			PublicAmountMode:         0,
			EncryptedUtxos:           "00",
			StateEntries: []txprover.ProofStateEntry{{
				Index: 0,
				Hash:  fieldInput(utxoHash),
			}},
			Inputs: []txprover.ProofInputRequest{{
				Utxo: txprover.ProofUtxoRequest{
					Domain:          fieldInput(utxo.Domain),
					OwnerP256Pubkey: parse.BytesHex(p256Pubkey),
					AssetID:         fieldInput(utxo.AssetID),
					AssetAmount:     fieldInput(utxo.AssetAmount),
					Blinding:        fieldInput(utxo.Blinding),
					DataHash:        fieldInput(utxo.DataHash),
					ZoneDataHash:    fieldInput(utxo.ZoneDataHash),
					ZoneProgramID:   fieldInput(utxo.ZoneProgramID),
				},
				LeafIndex:       0,
				NullifierSecret: fieldInput(nullifierSecret),
			}},
			Outputs: []txprover.ProofUtxoRequest{
				{
					Domain:        fieldInput(big.NewInt(7)),
					Owner:         fieldInput(owner),
					AssetID:       fieldInput(utxo.AssetID),
					AssetAmount:   fieldInput(big.NewInt(5)),
					Blinding:      fieldInput(big.NewInt(31)),
					DataHash:      fieldInput(big.NewInt(0)),
					ZoneDataHash:  fieldInput(big.NewInt(0)),
					ZoneProgramID: fieldInput(big.NewInt(0)),
				},
				{
					Domain:        fieldInput(big.NewInt(8)),
					Owner:         fieldInput(owner),
					AssetID:       fieldInput(utxo.AssetID),
					AssetAmount:   fieldInput(big.NewInt(0)),
					Blinding:      fieldInput(big.NewInt(37)),
					DataHash:      fieldInput(big.NewInt(0)),
					ZoneDataHash:  fieldInput(big.NewInt(0)),
					ZoneProgramID: fieldInput(big.NewInt(0)),
				},
			},
			ProgramIDHashchain: fieldInput(big.NewInt(0)),
			DataHash:           fieldInput(big.NewInt(0)),
			ZoneDataHash:       fieldInput(big.NewInt(0)),
		}},
	}, priv, p256Pubkey
}

func fieldInput(value *big.Int) string {
	return "0x" + parse.FieldHex(value)
}
