package spp

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestBuildProofSigningPayloadAllowsUnsignedP256Input(t *testing.T) {
	priv, err := fixedP256PrivateKey(big.NewInt(11))
	if err != nil {
		t.Fatal(err)
	}
	p256Pubkey := elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	nullifierSecret := big.NewInt(19)
	ownerKeyHash, err := P256OwnerKeyHash(p256Pubkey)
	if err != nil {
		t.Fatal(err)
	}
	nullifierPk, err := NullifierPk(nullifierSecret)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := OwnerHash(ownerKeyHash, nullifierPk)
	if err != nil {
		t.Fatal(err)
	}
	utxo := Utxo{
		Domain:          big.NewInt(7),
		Owner:           owner,
		AssetID:         big.NewInt(1),
		AssetAmount:     big.NewInt(5),
		Blinding:        big.NewInt(23),
		DataHash:        big.NewInt(0),
		PolicyData:      big.NewInt(0),
		PolicyProgramID: big.NewInt(0),
	}
	utxoHash, err := UtxoHash(utxo)
	if err != nil {
		t.Fatal(err)
	}

	request := ProofBundleRequest{
		SolanaSignerPubkey: proofBytesHex(make([]byte, 32)),
		Transactions: []ProofTransactionRequest{{
			Name:                     "unsigned-p256",
			InstructionDiscriminator: 1,
			ExpiryUnixTs:             123,
			SenderViewTag:            proofFieldHex(big.NewInt(9)),
			PublicAmountMode:         0,
			EncryptedUtxos:           "00",
			StateEntries: []ProofStateEntry{{
				Index: 0,
				Hash:  proofFieldHex(utxoHash),
			}},
			Inputs: []ProofInputRequest{{
				Utxo: ProofUtxoRequest{
					Domain:          proofFieldHex(utxo.Domain),
					OwnerP256Pubkey: proofBytesHex(p256Pubkey),
					AssetID:         proofFieldHex(utxo.AssetID),
					AssetAmount:     proofFieldHex(utxo.AssetAmount),
					Blinding:        proofFieldHex(utxo.Blinding),
					DataHash:        proofFieldHex(utxo.DataHash),
					PolicyData:      proofFieldHex(utxo.PolicyData),
					PolicyProgramID: proofFieldHex(utxo.PolicyProgramID),
				},
				LeafIndex:       0,
				NullifierSecret: proofFieldHex(nullifierSecret),
			}},
			ProgramIDHashchain: proofFieldHex(big.NewInt(0)),
			DataHash:           proofFieldHex(big.NewInt(0)),
			PolicyData:         proofFieldHex(big.NewInt(0)),
		}},
	}

	payload, err := BuildProofSigningPayload(&ProofSystem{Shape: Shape{NInputs: 1, NOutputs: 2}}, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.Transactions) != 1 {
		t.Fatalf("payload transaction count = %d, want 1", len(payload.Transactions))
	}
	if !payload.Transactions[0].RequiresP256Signature {
		t.Fatal("signing payload did not request a P256 signature")
	}
	if payload.Transactions[0].PrivateTxHash == proofFieldHex(big.NewInt(0)) {
		t.Fatal("private tx hash was zero")
	}

	if _, err := BuildProofBundle(&ProofSystem{Shape: Shape{NInputs: 1, NOutputs: 2}}, request); err == nil {
		t.Fatal("unsigned P256 proof bundle unexpectedly succeeded")
	}
}
