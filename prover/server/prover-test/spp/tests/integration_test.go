package tests

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"zolana/prover/prover-test/spp/internal/p256key"
	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
	txprover "zolana/prover/prover-test/spp/prover/transaction"
)

// The P256 ownership rail is removed: requests carrying P256-owned inputs are
// rejected by both the signing-payload and the proof-bundle builders.
func TestP256OwnedRequestRejected(t *testing.T) {
	request := p256ProofRequest(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	if _, err := txprover.BuildProofSigningPayload(&txprover.ProofSystem{Shape: shape}, request); err == nil {
		t.Fatal("P256-owned signing payload unexpectedly succeeded")
	}
	if _, err := txprover.BuildProofBundle(&txprover.ProofSystem{Shape: shape}, request); err == nil {
		t.Fatal("P256-owned proof bundle unexpectedly succeeded")
	}
}

func p256ProofRequest(t *testing.T) txprover.ProofBundleRequest {
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
		RingDataHash:  big.NewInt(0),
		RingProgramID: big.NewInt(0),
	}
	utxoHash, err := protocol.UtxoHash(utxo)
	if err != nil {
		t.Fatal(err)
	}

	return txprover.ProofBundleRequest{
		PayerPubkey: parse.BytesHex(make([]byte, 32)),
		Transactions: []txprover.ProofTransactionRequest{{
			Name:                     "p256-owned",
			InstructionDiscriminator: 1,
			ExpiryUnixTs:             123,
			SenderViewTag:            fieldInput(big.NewInt(9)),
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
					RingDataHash:    fieldInput(utxo.RingDataHash),
					RingProgramID:   fieldInput(utxo.RingProgramID),
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
					RingDataHash:  fieldInput(big.NewInt(0)),
					RingProgramID: fieldInput(big.NewInt(0)),
				},
				{
					Domain:        fieldInput(big.NewInt(protocol.UtxoDomain)),
					Owner:         fieldInput(owner),
					Asset:         fieldInput(utxo.Asset),
					Amount:        fieldInput(big.NewInt(0)),
					Blinding:      fieldInput(big.NewInt(37)),
					DataHash:      fieldInput(big.NewInt(0)),
					RingDataHash:  fieldInput(big.NewInt(0)),
					RingProgramID: fieldInput(big.NewInt(0)),
				},
			},
			DataHash:     fieldInput(big.NewInt(0)),
			RingDataHash: fieldInput(big.NewInt(0)),
		}},
	}
}

func fieldInput(value *big.Int) string {
	return "0x" + parse.FieldHex(value)
}
