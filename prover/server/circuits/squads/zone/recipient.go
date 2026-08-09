package squadszone

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
	squadsutils "zolana/prover/circuits/squads/utils"
	"zolana/prover/circuits/squads/utils/p256"
	"zolana/prover/circuits/verifiable-encryption/aes"
)

// The recipient ciphertext is AES-CTR over amount u64 || asset 32B from the
// UTXO || blinding 31B. Unlike the sender, the recipient transmits its
// blinding. There is no tag. Integrity comes from the Poseidon ciphertext
// hash folded into the public input hash.
const RecipientCiphertextLen = 8 + 32 + 31

// Recipient is public-only. The prover holds no recipient secret, so the
// recipient's public viewing key is passed in. ViewingPubkey is the 65-byte
// uncompressed P-256 point (0x04 || x || y).
type Recipient struct {
	Owner           frontend.Variable
	NullifierPubkey frontend.Variable
	ViewingPubkey   [65]frontend.Variable
}

// Hash folds the recipient's public account identity (owner, compressed viewing
// key, nullifier pk) for the public input hash. The on-chain program supplies
// the same values from the recipient's ViewingKeyAccount.
func (r Recipient) Hash(api frontend.API) frontend.Variable {
	compressed := p256.CompressPubkey(api, r.ViewingPubkey)
	pkLo, pkHi := squadsutils.Pack33To2FECircuit(api, compressed)
	return gadget.PoseidonHash(api, []frontend.Variable{
		r.Owner,
		pkLo,
		pkHi,
		r.NullifierPubkey,
	})
}

// Constrain enforces the recipient side and returns the ciphertext hash to fold
// into the public input hash. The recipient output is owned by the recipient
// (public owner binding, no secret checks), and amount‖asset‖blinding is
// verifiably encrypted to the recipient's viewing key via ECDH with the shared
// ephemeral key. txViewingSkBytes is the ephemeral scalar. txViewingPkComp is
// its compressed public key, bound to it by keypair consistency in Define.
func (r Recipient) Constrain(api frontend.API, g *aes.AESGadget, tx squadsutils.Transaction, txViewingSkBytes [32]frontend.Variable, txViewingPkComp [33]frontend.Variable) frontend.Variable {
	output := tx.Outputs[RecipientOutputIndex]

	ownerHash := abstractor.Call(api, shared.OwnerHashGadget{
		OwnerKeyHash: r.Owner,
		NullifierPk:  r.NullifierPubkey,
	})
	api.AssertIsEqual(output.OwnerHash, ownerHash)

	p256.PointOnCurve(api, r.ViewingPubkey)
	dh := p256.ECDH(api, txViewingSkBytes, r.ViewingPubkey)
	rpkComp := p256.CompressPubkey(api, r.ViewingPubkey)
	sharedSecret := squadsutils.DeriveSharedSecret(api, dh, txViewingPkComp, rpkComp)
	key, nonce := squadsutils.KeySchedule(api, sharedSecret, nil, 0)

	plaintext := recipientPlaintextBytes(api, output.Amount, output.Asset, output.Blinding)
	ciphertext := aes.CTREncrypt(api, g, key, nonce, plaintext[:])
	return gadget.PoseidonHash(api, squadsutils.PackBytesBE(api, ciphertext, 16))
}

func recipientPlaintextBytes(api frontend.API, amount, asset, blinding frontend.Variable) [RecipientCiphertextLen]frontend.Variable {
	var pt [RecipientCiphertextLen]frontend.Variable
	copy(pt[0:8], squadsutils.FieldToBytesBE(api, amount, 8))
	copy(pt[8:40], squadsutils.FieldToBytesBE(api, asset, 32))
	copy(pt[40:71], squadsutils.FieldToBytesBE(api, blinding, 31))
	return pt
}
