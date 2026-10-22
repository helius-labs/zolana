package squadskeyencryption

import (
	"circuits/ringutils"
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// ecdhEncrypt checks canonical tagged keys, rejects noncontributory peers,
// and commits to the ciphertext produced by the shared AES-256-CTR gadget.
func ecdhEncrypt(api frontend.API, ephBytes [32]frontend.Variable, ephPk, recipientPk [33]frontend.Variable, plaintext []frontend.Variable, info []byte) frontend.Variable {
	recipientU := ringutils.PublicKeyCoordinate(api, recipientPk)
	dh := x25519.ECDH(api, ephBytes, recipientU)
	sharedSecret := ringutils.DeriveSharedSecret(api, dh, ephPk, recipientPk)
	infoVars := make([]frontend.Variable, len(info))
	for i, b := range info {
		infoVars[i] = b
	}
	key, nonce := ringutils.KeySchedule(api, sharedSecret, infoVars, len(infoVars))
	ciphertext := aes.NewCipher(api, key).CTREncrypt(nonce, plaintext)
	return gadget.HashBytes(api, ciphertext)
}
