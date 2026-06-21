package merge

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/circuits/verifiable-encryption/aes"
	"zolana/prover/circuits/verifiable-encryption/p256"
)

// mergeInfo is the HPKE-style key-schedule info string bound into the KDF
// (spec Merge Proof Verifiable encryption: info = "TSPP/merge").
var mergeInfo = []byte("TSPP/merge")

// MergePlaintextLen is the AES-CTR plaintext: amount (u64, 8 BE bytes) || asset
// (32 BE bytes from the UTXO) || blinding (31 BE bytes). The owner is bound
// separately through output_utxo_hash, so it is not transmitted. No GCM tag;
// integrity comes from the Poseidon ciphertext hash folded into the public input
// hash and from the plaintext-to-output binding.
const MergePlaintextLen = 8 + 32 + 31

// constrainEncryption proves the verifiable encryption of the merged output to
// the owner's viewing key and returns the Poseidon ciphertext hash plus the two
// field limbs of the compressed tx_viewing_pk, all folded into the public input
// hash. tx_viewing_pk is derived (not witnessed) as tx_viewing_sk · G_P256, so
// keypair consistency holds by construction.
func (c *Circuit) constrainEncryption(api frontend.API, g *aes.AESGadget) (ctHash, txViewingPkLo, txViewingPkHi frontend.Variable) {
	var skBytes [32]frontend.Variable
	copy(skBytes[:], ve.FieldToBytesBE(api, c.TxViewingSk, 32))

	// Keypair consistency: tx_viewing_pk == tx_viewing_sk · G_P256.
	txViewingPkComp := p256.CompressPubkey(api, p256.ScalarMulGenerator(api, skBytes))

	// ECDH against the owner's viewing key under the ephemeral tx_viewing_sk.
	p256.PointOnCurve(api, c.UserViewingPubkey)
	dh := p256.ECDH(api, skBytes, c.UserViewingPubkey)
	rpkComp := p256.CompressPubkey(api, c.UserViewingPubkey)
	sharedSecret := ve.DeriveSharedSecret(api, dh, txViewingPkComp, rpkComp)

	key, nonce := ve.KeySchedule(api, sharedSecret, mergeInfoBytes(), len(mergeInfo))

	plaintext := mergePlaintextBytes(api, c.Output.Utxo.Amount, c.Output.Utxo.Asset, c.Output.Utxo.Blinding)
	ciphertext := aes.CTREncrypt(api, g, key, nonce, plaintext[:])
	ctHash = gadget.PoseidonHash(api, ve.PackBytesBE(api, ciphertext, 16))

	txViewingPkLo, txViewingPkHi = ve.Pack33To2FECircuit(api, txViewingPkComp)
	return ctHash, txViewingPkLo, txViewingPkHi
}

func mergeInfoBytes() []frontend.Variable {
	out := make([]frontend.Variable, len(mergeInfo))
	for i, b := range mergeInfo {
		out[i] = frontend.Variable(b)
	}
	return out
}

// mergePlaintextBytes lays out amount (8 BE bytes), asset (32 BE bytes), and
// blinding (31 BE bytes), all read from the merged output UTXO.
func mergePlaintextBytes(api frontend.API, amount, asset, blinding frontend.Variable) [MergePlaintextLen]frontend.Variable {
	var pt [MergePlaintextLen]frontend.Variable
	copy(pt[0:8], ve.FieldToBytesBE(api, amount, 8))
	copy(pt[8:40], ve.FieldToBytesBE(api, asset, 32))
	copy(pt[40:71], ve.FieldToBytesBE(api, blinding, 31))
	return pt
}
