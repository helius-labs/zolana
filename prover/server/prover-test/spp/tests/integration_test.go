package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"zolana/prover/prover-test/spp/internal/p256key"
	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
	txprover "zolana/prover/prover-test/spp/prover/transaction"
)

func TestBuildProofSigningPayloadAllowsUnsignedP256Input(t *testing.T) {
	request, _, _ := p256ProofRequest(t)

	payload, err := txprover.BuildProofSigningPayload(&txprover.ProofSystem{Shape: protocol.Shape{NInputs: 1, NOutputs: 2}}, request)
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
	if payload.Transactions[0].P256MessageHash == parse.FieldHex(big.NewInt(0)) {
		t.Fatal("P256 message hash was zero")
	}
	privateTxHash, err := parse.Field("0x" + payload.Transactions[0].PrivateTxHash)
	if err != nil {
		t.Fatal(err)
	}
	expectedDigest, err := protocol.P256MessageDigest(privateTxHash)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Transactions[0].P256MessageHash != parse.BytesHex(expectedDigest[:]) {
		t.Fatalf(
			"P256 message hash = %q, want %q",
			payload.Transactions[0].P256MessageHash,
			parse.BytesHex(expectedDigest[:]),
		)
	}

	if _, err := txprover.BuildProofBundle(&txprover.ProofSystem{Shape: protocol.Shape{NInputs: 1, NOutputs: 2}}, request); err == nil {
		t.Fatal("unsigned P256 proof bundle unexpectedly succeeded")
	}
}

func TestBuildProofBundleAcceptsSignedP256Input(t *testing.T) {
	request, priv, p256Pubkey := p256ProofRequest(t)
	payload, err := txprover.BuildProofSigningPayload(&txprover.ProofSystem{Shape: protocol.Shape{NInputs: 1, NOutputs: 2}}, request)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := parse.Hex32(payload.Transactions[0].P256MessageHash)
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

	ps, err := txprover.Setup(protocol.Shape{NInputs: 1, NOutputs: 2}, txprover.TransactionRequiresP256(*tx))
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
	ownerKeyHash, err := protocol.OwnerPkField(p256Pubkey)
	if err != nil {
		t.Fatal(err)
	}
	nullifierPk, err := protocol.NullifierPk(nullifierSecret)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := protocol.OwnerHash(ownerKeyHash, nullifierPk)
	if err != nil {
		t.Fatal(err)
	}
	utxo := protocol.Utxo{
		Domain:        big.NewInt(protocol.UtxoDomain),
		Owner:         owner,
		Asset:         big.NewInt(1),
		Amount:        big.NewInt(5),
		Blinding:      big.NewInt(23),
		DataHash:      big.NewInt(0),
		ZoneDataHash:  big.NewInt(0),
		ZoneProgramID: big.NewInt(0),
	}
	utxoHash, err := protocol.UtxoHash(utxo)
	if err != nil {
		t.Fatal(err)
	}

	return txprover.ProofBundleRequest{
		PayerPubkey: parse.BytesHex(make([]byte, 32)),
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
					Asset:           fieldInput(utxo.Asset),
					Amount:          fieldInput(utxo.Amount),
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
					Domain:        fieldInput(big.NewInt(protocol.UtxoDomain)),
					Owner:         fieldInput(owner),
					Asset:         fieldInput(utxo.Asset),
					Amount:        fieldInput(big.NewInt(5)),
					Blinding:      fieldInput(big.NewInt(31)),
					DataHash:      fieldInput(big.NewInt(0)),
					ZoneDataHash:  fieldInput(big.NewInt(0)),
					ZoneProgramID: fieldInput(big.NewInt(0)),
				},
				{
					Domain:        fieldInput(big.NewInt(protocol.UtxoDomain)),
					Owner:         fieldInput(owner),
					Asset:         fieldInput(utxo.Asset),
					Amount:        fieldInput(big.NewInt(0)),
					Blinding:      fieldInput(big.NewInt(37)),
					DataHash:      fieldInput(big.NewInt(0)),
					ZoneDataHash:  fieldInput(big.NewInt(0)),
					ZoneProgramID: fieldInput(big.NewInt(0)),
				},
			},
			DataHash:     fieldInput(big.NewInt(0)),
			ZoneDataHash: fieldInput(big.NewInt(0)),
		}},
	}, priv, p256Pubkey
}

func fieldInput(value *big.Int) string {
	return "0x" + parse.FieldHex(value)
}
