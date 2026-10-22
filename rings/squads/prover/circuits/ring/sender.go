package squadsring

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"circuits/ringutils"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

var (
	labelTxViewing = new(big.Int).SetBytes([]byte("TSPP/tx_viewing"))
	labelBlinding  = new(big.Int).SetBytes([]byte("blinding"))
)

// SenderCiphertextLen: AES-CTR over the change plaintext (amount u64 || asset
// 32B read from the UTXO, diverging from the spec's asset_id). No tag; integrity
// comes from the Poseidon ciphertext hash folded into the public input hash.
const SenderCiphertextLen = 8 + 32

type Sender struct {
	Account ViewingKeyAccount
}

// deriveTxViewingSk runs the squads Poseidon-KDF chain to the ephemeral
// tx_viewing_sk (squads_policy_program.md, Ring Proof):
//
//	view_root         = PoseidonKDF(viewing_sk)
//	tx_viewing_secret = PoseidonKDF(view_root, "TSPP/tx_viewing")
//	tx_viewing_sk     = PoseidonKDF(tx_viewing_secret, first_nullifier)
func deriveTxViewingSk(api frontend.API, viewingSk [32]frontend.Variable, firstNullifier frontend.Variable) (frontend.Variable, error) {
	skLow, skHigh := ringutils.ViewingKeyLimbs(api, viewingSk)

	viewRoot := ringutils.PoseidonKDF(api, skLow, skHigh)
	txViewingSecret := ringutils.PoseidonKDF(api, viewRoot, labelTxViewing)
	return ringutils.PoseidonKDF(api, txViewingSecret, firstNullifier), nil
}

// FirstNullifier recomputes the nullifier of Inputs[0] under the sender's
// nullifier secret, the same value SPP publishes as its first nullifier.
func (s Sender) FirstNullifier(api frontend.API, tx ringutils.Transaction) frontend.Variable {
	firstInput := tx.Inputs[0]
	return abstractor.Call(api, transaction.NullifierGadget{
		UtxoHash:        firstInput.Hash(api),
		Blinding:        firstInput.Blinding,
		NullifierSecret: s.Account.Private.NullifierSecret,
	})
}

// DeriveTxViewingSk derives the shared ephemeral tx_viewing_sk from the first
// nullifier and the sender's viewing secret. One ephemeral key covers every
// ciphertext in the transaction, so it is derived once and reused for the
// recipient.
func (s Sender) DeriveTxViewingSk(api frontend.API, firstNullifier frontend.Variable) (frontend.Variable, error) {
	return deriveTxViewingSk(api, s.Account.Private.SharedViewingSecretKey, firstNullifier)
}

// DeriveBlindingSeed derives the SPP blinding_seed from tx_viewing_sk, so the
// holder of the shared viewing secret recomputes every output blinding and the
// private tx blinding without them being transmitted.
func DeriveBlindingSeed(api frontend.API, txViewingSk frontend.Variable) frontend.Variable {
	return ringutils.PoseidonKDF(api, txViewingSk, labelBlinding)
}

// Constrain enforces the full sender side and returns the ciphertext hash to
// fold into the public input hash:
//  1. account binding against the sender change output (owner, nullifier pk,
//     shared-viewing-secret commitment);
//  2. value conservation over the spent inputs;
//  3. the change output's blinding equals the SPP output blinding derived from
//     the blinding seed;
//  4. verifiable encryption of (amount, asset) under a key/nonce derived from
//     the shared tx_viewing_sk.
func (s Sender) Constrain(api frontend.API, tx ringutils.Transaction, txViewingSk, changeBlinding, publicAmount, recipientAmount frontend.Variable) (frontend.Variable, error) {
	if err := s.Account.Constrain(api, tx, SenderOutputIndex); err != nil {
		return nil, err
	}

	output := tx.Outputs[SenderOutputIndex]

	// Value conservation (single asset): inputs == sender change + public amount
	// + recipient amount. Enforced on every path, so a proposal-less withdrawal
	// still binds public_amount to the spent inputs and the change output.
	sumInputs := frontend.Variable(0)
	for i := range tx.Inputs {
		sumInputs = api.Add(sumInputs, tx.Inputs[i].Amount)
	}
	api.AssertIsEqual(sumInputs, api.Add(api.Add(output.Amount, publicAmount), recipientAmount))

	api.AssertIsEqual(output.Blinding, changeBlinding)

	key, nonce := ringutils.KeySchedule(api, txViewingSk, nil, 0)
	return s.ConstrainEncryption(api, key, nonce, output.Amount, output.Asset), nil
}

// ConstrainEncryption is the sender's verifiable encryption: it AES-CTR encrypts
// the change plaintext (amount || asset, both read from the sender output UTXO)
// under the given key/nonce and returns one Poseidon hash of the ciphertext to
// fold into the public input hash.
func (s Sender) ConstrainEncryption(api frontend.API, key [32]frontend.Variable, nonce [12]frontend.Variable, amount, asset frontend.Variable) frontend.Variable {
	plaintext := senderPlaintextBytes(api, amount, asset)
	ciphertext := aes.NewCipher(api, key).CTREncrypt(nonce, plaintext[:])
	return gadget.HashBytes(api, ciphertext)
}

// senderPlaintextBytes lays out amount (u64, 8 big-endian bytes) followed by
// asset (32 big-endian bytes from the UTXO).
func senderPlaintextBytes(api frontend.API, amount, asset frontend.Variable) [SenderCiphertextLen]frontend.Variable {
	var pt [SenderCiphertextLen]frontend.Variable
	copy(pt[0:8], ringutils.FieldToBytesBE(api, amount, 8))
	copy(pt[8:40], ringutils.FieldToBytesBE(api, asset, 32))
	return pt
}
