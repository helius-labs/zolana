package base

import (
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	ve "github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/aes"
)

// DomSepCRShared is "CR_S", the shared secret tag the Rust host derivation also uses.
const DomSepCRShared uint32 = 0x43525f53

// Envelope encrypts Plaintext to the X25519 key AuditorPk under the ephemeral secret EphSk.
type Envelope struct {
	Plaintext []frontend.Variable
	EphSk     [32]frontend.Variable
	AuditorPk [32]frontend.Variable
	Info      string
}

// Sealed carries both tagged keys packed with gadget.PackBytesBE and the ciphertext.
type Sealed struct {
	Auditor, Eph, Ciphertext []frontend.Variable
}

// Seal checks the key bytes, a canonical auditor key and a nonzero DH, the caller checks the plaintext bytes.
func (e Envelope) Seal(api frontend.API) Sealed {
	auditor, eph, dh := AgreeAuditKey(api, e.EphSk, e.AuditorPk)
	sealed := Sealed{Auditor: gadget.PackBytesBE(api, auditor[:]), Eph: gadget.PackBytesBE(api, eph[:])}
	// Binding both keys keeps the key schedule input from replaying under another key pair.
	secret := gadget.PoseidonHash(api, slices.Concat([]frontend.Variable{uint64(DomSepCRShared)}, gadget.PackBytesBE(api, dh[:]), sealed.Eph, sealed.Auditor))
	key, nonce := ve.KeySchedule(api, secret, ConstBytes(e.Info), len(e.Info))
	sealed.Ciphertext = aes.NewCipher(api, key).CTREncrypt(nonce, e.Plaintext)
	return sealed
}
