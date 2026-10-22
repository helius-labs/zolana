package squadsring

import (
	"github.com/consensys/gnark/frontend"

	"circuits/ringutils"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// RecipientCiphertextLen: AES-CTR over the recipient plaintext (amount u64 ||
// asset 32B from the UTXO || blinding 32B). Unlike the sender, the recipient
// transmits its blinding. No tag; integrity comes from the Poseidon ciphertext
// hash folded into the public input hash.
const RecipientCiphertextLen = 8 + 32 + 32

// Recipient is public-only: the prover holds no recipient secret, so the
// recipient's public viewing key is passed in. ViewingPubkey is the 33-byte
// tagged canonical X25519 public key (0x04 || u).
type Recipient struct {
	Owner           frontend.Variable
	NullifierPubkey frontend.Variable
	ViewingPubkey   [33]frontend.Variable
}

// Hash folds the recipient's public account identity (owner, tagged viewing
// key, nullifier pk) for the public input hash; the on-chain program supplies
// the same values from the recipient's ViewingKeyAccount.
func (r Recipient) Hash(api frontend.API) frontend.Variable {
	compressed := r.ViewingPubkey
	pkLo, pkHi := ringutils.Pack33To2FECircuit(api, compressed)
	return gadget.PoseidonHash(api, []frontend.Variable{
		r.Owner,
		pkLo,
		pkHi,
		r.NullifierPubkey,
	})
}

// Constrain enforces the recipient side and returns the ciphertext hash to fold
// into the public input hash: the recipient output is owned by the recipient
// (public owner binding, no secret checks), and amount‖asset‖blinding is
// verifiably encrypted to the recipient's viewing key via ECDH with the shared
// ephemeral key. txViewingSkBytes is the ephemeral scalar; txViewingPkComp is
// its tagged public key, bound to it by keypair consistency in Define.
func (r Recipient) Constrain(api frontend.API, tx ringutils.Transaction, txViewingSkBytes [32]frontend.Variable, txViewingPkComp [33]frontend.Variable) frontend.Variable {
	output := tx.Outputs[RecipientOutputIndex]

	api.AssertIsEqual(output.OwnerHash, ownerHash(api, r.Owner, r.NullifierPubkey))

	rpkComp := r.ViewingPubkey
	u := ringutils.PublicKeyCoordinate(api, rpkComp)
	dh := x25519.ECDH(api, txViewingSkBytes, u)
	sharedSecret := ringutils.DeriveSharedSecret(api, dh, txViewingPkComp, rpkComp)
	key, nonce := ringutils.KeySchedule(api, sharedSecret, nil, 0)

	plaintext := recipientPlaintextBytes(api, output.Amount, output.Asset, output.Blinding)
	ciphertext := aes.NewCipher(api, key).CTREncrypt(nonce, plaintext[:])
	return gadget.HashBytes(api, ciphertext)
}

// recipientPlaintextBytes lays out amount (8 BE bytes), asset (32 BE bytes),
// and blinding (32 BE bytes), all read from the recipient output UTXO.
func recipientPlaintextBytes(api frontend.API, amount, asset, blinding frontend.Variable) [RecipientCiphertextLen]frontend.Variable {
	var pt [RecipientCiphertextLen]frontend.Variable
	copy(pt[0:8], ringutils.FieldToBytesBE(api, amount, 8))
	copy(pt[8:40], ringutils.FieldToBytesBE(api, asset, 32))
	copy(pt[40:72], ringutils.FieldToBytesBE(api, blinding, 32))
	return pt
}
