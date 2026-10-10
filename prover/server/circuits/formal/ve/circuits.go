// Package ve holds fixed-dimension circuits over the verifiable-encryption
// gadgets for Lean extraction (formal-verification/VerifiableEncryption).
package ve

import (
	"crypto/elliptic"

	"github.com/consensys/gnark/frontend"

	verifiableencryption "zolana/prover/circuits/verifiable-encryption"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
	"zolana/prover/circuits/verifiable-encryption/aes"
	"zolana/prover/circuits/verifiable-encryption/p256"
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve"
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

const EnvelopePlaintextBytes = 16

var (
	SecretTag = []byte("TMES")
	KdfInfo   = []byte("TMEC")
)

// FieldMulCheck is one reduced product A * B modulo p.
type FieldMulCheck struct {
	A, B [8]frontend.Variable
	Out  [8]frontend.Variable `gnark:",public"`
}

func (c *FieldMulCheck) Define(api frontend.API) error {
	fp := emfield.NewFor(api, elliptic.P256().Params().P, emfield.LookupLayout)
	product := fp.GadgetEval(emfield.T(1, fp.Reduced(c.A[:]), fp.Reduced(c.B[:])))
	for i, limb := range product.Limbs() {
		api.AssertIsEqual(limb, c.Out[i])
	}
	return nil
}

// GuardedAdd is the incomplete affine addition behind the distinct-x guard.
type GuardedAdd struct {
	PX, PY, QX, QY [8]frontend.Variable
	RX, RY         [8]frontend.Variable `gnark:",public"`
}

func (c *GuardedAdd) Define(api frontend.API) error {
	rx, ry := emcurve.FormalGuardedAdd(api, c.PX[:], c.PY[:], c.QX[:], c.QY[:])
	for i := range rx {
		api.AssertIsEqual(rx[i], c.RX[i])
		api.AssertIsEqual(ry[i], c.RY[i])
	}
	return nil
}

// AgreeKey is p256.ComputeKeyAgreement with its six packed outputs in the
// KeyAgreement field order.
type AgreeKey struct {
	EphemeralSk [32]frontend.Variable
	RecipientPk [65]frontend.Variable
	Packed      [6]frontend.Variable `gnark:",public"`
}

func (c *AgreeKey) Define(api frontend.API) error {
	k := p256.ComputeKeyAgreement(api, c.EphemeralSk, c.RecipientPk)
	for i, v := range []frontend.Variable{k.RecipientLo, k.RecipientHi, k.EphemeralLo, k.EphemeralHi, k.SharedLo, k.SharedHi} {
		api.AssertIsEqual(v, c.Packed[i])
	}
	return nil
}

// DerivePublicKey is p256.DerivePublicKey with the x-coordinate bytes and the
// packed compressed key.
type DerivePublicKey struct {
	Sk     [32]frontend.Variable
	X      [32]frontend.Variable `gnark:",public"`
	Lo, Hi frontend.Variable     `gnark:",public"`
}

func (c *DerivePublicKey) Define(api frontend.API) error {
	key := p256.DerivePublicKey(api, c.Sk)
	lo, hi := key.Packed(api)
	api.AssertIsEqual(lo, c.Lo)
	api.AssertIsEqual(hi, c.Hi)
	compressed := key.Compressed(api)
	for i := range c.X {
		api.AssertIsEqual(compressed[1+i], c.X[i])
	}
	return nil
}

// AesCtrBlock is AES-256-CTR over one block at the first counter.
type AesCtrBlock struct {
	Key        [32]frontend.Variable
	Nonce      [12]frontend.Variable
	Plaintext  [16]frontend.Variable
	Ciphertext [16]frontend.Variable `gnark:",public"`
}

func (c *AesCtrBlock) Define(api frontend.API) error {
	ciphertext := aes.NewCipher(api, c.Key).CTREncrypt(c.Nonce, c.Plaintext[:])
	for i, b := range ciphertext {
		api.AssertIsEqual(b, c.Ciphertext[i])
	}
	return nil
}

// KeySchedule is the Poseidon KDF under the fixed KdfInfo label.
type KeySchedule struct {
	SharedSecret frontend.Variable
	Key          [32]frontend.Variable `gnark:",public"`
	Nonce        [12]frontend.Variable `gnark:",public"`
}

func (c *KeySchedule) Define(api frontend.API) error {
	key, nonce := verifiableencryption.KeySchedule(api, c.SharedSecret, KdfInfo)
	for i := range key {
		api.AssertIsEqual(key[i], c.Key[i])
	}
	for i := range nonce {
		api.AssertIsEqual(nonce[i], c.Nonce[i])
	}
	return nil
}

// EnvelopeMerge is the envelope exactly as the default merge rail
// (spp_merge/default.go) instantiates it: merge's secret tag and KDF label,
// the 40-byte merge plaintext and the first nullifier as Context. Its public
// outputs are what merge feeds onward: the four packed envelope elements of
// the public input hash and the output blinding derived from the shared
// secret.
type EnvelopeMerge struct {
	EphemeralSk [32]frontend.Variable
	RecipientPk [65]frontend.Variable
	Plaintext   [mergeshared.MergeCiphertextBytes]frontend.Variable
	Context     frontend.Variable
	Elements    [4]frontend.Variable `gnark:",public"`
	Blinding    frontend.Variable    `gnark:",public"`
}

func (c *EnvelopeMerge) Define(api frontend.API) error {
	encrypted := verifiableencryption.Envelope{
		SecretTag:   mergeshared.MergeSecretTag,
		KdfInfo:     mergeshared.MergeKdfInfo,
		EphemeralSk: c.EphemeralSk,
		RecipientPk: c.RecipientPk,
		Plaintext:   c.Plaintext[:],
		Context:     c.Context,
	}.Encrypt(api)
	for i, e := range mergeshared.EnvelopePublicElements(api, encrypted) {
		api.AssertIsEqual(e, c.Elements[i])
	}
	api.AssertIsEqual(mergeshared.MergeDerivedBlinding(api, encrypted.SharedSecret), c.Blinding)
	return nil
}

// Envelope is the ECIES envelope over a 16-byte plaintext with the fixed
// SecretTag and KdfInfo, mirroring the envelope test circuit.
type Envelope struct {
	EphemeralSk [32]frontend.Variable
	RecipientPk [65]frontend.Variable
	Plaintext   [EnvelopePlaintextBytes]frontend.Variable
	RecipientLo frontend.Variable                         `gnark:",public"`
	RecipientHi frontend.Variable                         `gnark:",public"`
	EphemeralLo frontend.Variable                         `gnark:",public"`
	EphemeralHi frontend.Variable                         `gnark:",public"`
	Ciphertext  [EnvelopePlaintextBytes]frontend.Variable `gnark:",public"`
}

func (c *Envelope) Define(api frontend.API) error {
	encrypted := verifiableencryption.Envelope{
		SecretTag:   SecretTag,
		KdfInfo:     KdfInfo,
		EphemeralSk: c.EphemeralSk,
		RecipientPk: c.RecipientPk,
		Plaintext:   c.Plaintext[:],
	}.Encrypt(api)
	api.AssertIsEqual(encrypted.RecipientLo, c.RecipientLo)
	api.AssertIsEqual(encrypted.RecipientHi, c.RecipientHi)
	api.AssertIsEqual(encrypted.EphemeralLo, c.EphemeralLo)
	api.AssertIsEqual(encrypted.EphemeralHi, c.EphemeralHi)
	for i, b := range encrypted.Ciphertext {
		api.AssertIsEqual(b, c.Ciphertext[i])
	}
	return nil
}
