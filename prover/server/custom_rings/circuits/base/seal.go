package base

import (
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	ve "github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/aes"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/p256"
)

// DomSepCRShared is "CR_S", the shared secret tag the Rust host derivation also uses.
const DomSepCRShared uint32 = 0x43525f53

// Envelope encrypts Plaintext to AuditorPk under the ephemeral key EphSk.
type Envelope struct {
	Plaintext []frontend.Variable
	EphSk     [32]frontend.Variable
	AuditorPk [65]frontend.Variable
	Info      string
}

// Sealed carries both compressed keys packed with gadget.PackBytesBE and the ciphertext.
type Sealed struct {
	Auditor, Eph, Ciphertext []frontend.Variable
}

// Seal checks the key bytes, the auditor point and 0 < EphSk < n, the caller checks the plaintext bytes.
func (e Envelope) Seal(api frontend.API, rc frontend.Rangechecker) Sealed {
	CheckBytes(rc, e.EphSk[:], e.AuditorPk[:])
	// The compression gadget reads the prefix from the y parity, never from byte 0.
	api.AssertIsEqual(e.AuditorPk[0], 4)
	p256.PointOnCurve(api, e.AuditorPk)
	p256.AssertScalarInRange(api, e.EphSk)
	auditor := p256.CompressPubkey(api, e.AuditorPk)
	eph := p256.CompressPubkey(api, p256.ScalarMulGenerator(api, e.EphSk))
	dh := p256.ECDH(api, e.EphSk, e.AuditorPk)
	sealed := Sealed{Auditor: gadget.PackBytesBE(api, auditor[:]), Eph: gadget.PackBytesBE(api, eph[:])}
	// Binding both keys keeps the key schedule input from replaying under another key pair.
	secret := gadget.PoseidonHash(api, slices.Concat([]frontend.Variable{uint64(DomSepCRShared)}, gadget.PackBytesBE(api, dh[:]), sealed.Eph, sealed.Auditor))
	key, nonce := ve.KeySchedule(api, secret, ConstBytes(e.Info), len(e.Info))
	sealed.Ciphertext = aes.CTREncrypt(api, aes.NewAESGadget(api), key, nonce, e.Plaintext)
	return sealed
}
