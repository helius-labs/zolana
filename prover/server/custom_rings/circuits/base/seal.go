package base

import (
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	ve "github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/aes"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/x25519"
)

// DomSepCRShared is "CR_S", the shared secret tag the Rust host derivation also uses.
const DomSepCRShared uint32 = 0x43525f53

// Envelope encrypts Plaintext to the X25519 key AuditorPk under the ephemeral secret EphSk.
type Envelope struct {
	Compact   bool
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
	var auditor, eph [33]frontend.Variable
	var dh [32]frontend.Variable
	if e.Compact {
		assertCanonicalX25519Compact(api, e.AuditorPk)
		dh = x25519.ECDH(api, e.EphSk, e.AuditorPk)
		pub := x25519.ScalarMulGenerator(api, e.EphSk)
		auditor[0], eph[0] = 4, 4
		copy(auditor[1:], e.AuditorPk[:])
		copy(eph[1:], pub[:])
	} else {
		auditor, eph, dh = AgreeAuditKey(api, e.EphSk, e.AuditorPk)
	}
	sealed := Sealed{Auditor: gadget.PackBytesBE(api, auditor[:]), Eph: gadget.PackBytesBE(api, eph[:])}
	// Binding both keys keeps the key schedule input from replaying under another key pair.
	secret := gadget.PoseidonHash(api, slices.Concat([]frontend.Variable{uint64(DomSepCRShared)}, gadget.PackBytesBE(api, dh[:]), sealed.Eph, sealed.Auditor))
	var key [32]frontend.Variable
	var nonce [12]frontend.Variable
	if e.Info == auditEncInfo {
		key, nonce = auditStreamKeySchedule(api, secret)
	} else {
		key, nonce = ve.KeySchedule(api, secret, ConstBytes(e.Info), len(e.Info))
	}
	sealed.Ciphertext = aes.NewCipher(api, key).CTREncrypt(nonce, e.Plaintext)
	return sealed
}
