package squadszone

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction"
	"zolana/prover/circuits/verifiable-encryption/aes"
	zoneutils "zolana/prover/circuits/zone-utils"
	"zolana/prover/circuits/zone-utils/p256"
)

// RecipientCiphertextLen: AES-CTR over the recipient plaintext (amount u64 ||
// asset 32B from the UTXO || blinding 31B). Unlike the sender, the recipient
// transmits its blinding. No tag; integrity comes from the Poseidon ciphertext
// hash folded into the public input hash.
const RecipientCiphertextLen = 8 + 32 + 31

// Recipient is public-only: the prover holds no recipient secret, so the
// recipient's public viewing key is passed in. ViewingPubkey is the 65-byte
// uncompressed P-256 point (0x04 || x || y).
type Recipient struct {
	Owner           frontend.Variable
	NullifierPubkey frontend.Variable
	ViewingPubkey   [65]frontend.Variable
}

// Hash folds the recipient's public account identity (owner, compressed viewing
// key, nullifier pk) for the public input hash; the on-chain program supplies
// the same values from the recipient's ViewingKeyAccount.
func (r Recipient) Hash(api frontend.API) frontend.Variable {
	compressed := p256.CompressPubkey(api, r.ViewingPubkey)
	pkLo, pkHi := zoneutils.Pack33To2FECircuit(api, compressed)
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
// its compressed public key, bound to it by keypair consistency in Define.
func (r Recipient) Constrain(api frontend.API, g *aes.AESGadget, tx zoneutils.Transaction, txViewingSkBytes [32]frontend.Variable, txViewingPkComp [33]frontend.Variable) frontend.Variable {
	output := tx.Outputs[RecipientOutputIndex]

	ownerHash := abstractor.Call(api, transaction.OwnerHashGadget{
		OwnerKeyHash: r.Owner,
		NullifierPk:  r.NullifierPubkey,
	})
	api.AssertIsEqual(output.OwnerHash, ownerHash)

	p256.PointOnCurve(api, r.ViewingPubkey)
	dh := p256.ECDH(api, txViewingSkBytes, r.ViewingPubkey)
	rpkComp := p256.CompressPubkey(api, r.ViewingPubkey)
	sharedSecret := zoneutils.DeriveSharedSecret(api, dh, txViewingPkComp, rpkComp)
	key, nonce := zoneutils.KeySchedule(api, sharedSecret, nil, 0)

	plaintext := recipientPlaintextBytes(api, output.Amount, output.Asset, output.Blinding)
	ciphertext := aes.CTREncrypt(api, g, key, nonce, plaintext[:])
	return gadget.PoseidonHash(api, zoneutils.PackBytesBE(api, ciphertext, 16))
}

// recipientPlaintextBytes lays out amount (8 BE bytes), asset (32 BE bytes),
// and blinding (31 BE bytes), all read from the recipient output UTXO.
func recipientPlaintextBytes(api frontend.API, amount, asset, blinding frontend.Variable) [RecipientCiphertextLen]frontend.Variable {
	var pt [RecipientCiphertextLen]frontend.Variable
	copy(pt[0:8], zoneutils.FieldToBytesBE(api, amount, 8))
	copy(pt[8:40], zoneutils.FieldToBytesBE(api, asset, 32))
	copy(pt[40:71], zoneutils.FieldToBytesBE(api, blinding, 31))
	return pt
}
