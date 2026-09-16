// Package deposit binds every deposited owner's commitment to an opening
// encrypted for the configured auditor.
package deposit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"zolana/prover/circuits/custom_ring/base"
	"zolana/prover/circuits/gadget"
	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/circuits/verifiable-encryption/aes"
	"zolana/prover/circuits/verifiable-encryption/p256"
)

const MaxDeposits = 8
const OpeningBytes = 64
const Domain uint32 = 0x43524450 // CRDP
const EncryptionInfo = "CRING/dep1"

// Each owner commitment must match the opening encrypted for the auditor.
type CustomRingDepositCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	ContextHash     frontend.Variable
	Count           frontend.Variable
	OwnerHashes     [MaxDeposits]frontend.Variable
	Blindings       [MaxDeposits]frontend.Variable
	EphSk           [32]frontend.Variable
	AuditorPk       [65]frontend.Variable
}

func (c *CustomRingDepositCircuit) Define(api frontend.API) error {
	// 1. Prove exactly the occupied prefix with canonical zero padding.
	var countMatches [MaxDeposits]frontend.Variable
	validCount := frontend.Variable(0)
	for i := range countMatches {
		countMatches[i] = api.IsZero(api.Sub(c.Count, i+1))
		validCount = api.Add(validCount, countMatches[i])
	}
	api.AssertIsEqual(validCount, 1)
	var enabled [MaxDeposits]frontend.Variable
	plaintext := make([]frontend.Variable, MaxDeposits*OpeningBytes)
	for i := range c.OwnerHashes {
		enabled[i] = frontend.Variable(0)
		for _, count := range countMatches[i:] {
			enabled[i] = api.Add(enabled[i], count)
		}
		disabled := api.Sub(1, enabled[i])
		api.AssertIsEqual(api.Mul(disabled, c.OwnerHashes[i]), 0)
		api.AssertIsEqual(api.Mul(disabled, c.Blindings[i]), 0)
		owner, blinding := canonicalBytes(api, c.OwnerHashes[i]), canonicalBytes(api, c.Blindings[i])
		copy(plaintext[i*OpeningBytes:], owner[:])
		copy(plaintext[i*OpeningBytes+32:], blinding[:])
	}

	// 2. Bind the shared key to the auditor and published ephemeral key.
	rangeChecker := rangecheck.New(api)
	for _, b := range c.EphSk {
		rangeChecker.Check(b, 8)
	}
	for _, b := range c.AuditorPk {
		rangeChecker.Check(b, 8)
	}
	api.AssertIsEqual(c.AuditorPk[0], 4)
	p256.PointOnCurve(api, c.AuditorPk)
	auditor := p256.CompressPubkey(api, c.AuditorPk)
	ephemeral := p256.CompressPubkey(api, p256.ScalarMulGenerator(api, c.EphSk))
	dh := p256.ECDH(api, c.EphSk, c.AuditorPk)
	secret := base.DeriveAuditSharedSecret(api, dh, ephemeral, auditor)
	info := make([]frontend.Variable, len(EncryptionInfo))
	for i, b := range []byte(EncryptionInfo) {
		info[i] = b
	}
	key, nonce := ve.KeySchedule(api, secret, info, len(info))

	// 3. Assign distinct CTR blocks to every deposit opening.
	ciphertext := aes.CTREncrypt(api, aes.NewAESGadget(api), key, nonce, plaintext)
	chain := []frontend.Variable{Domain, c.ContextHash, c.Count}
	for i := range c.OwnerHashes {
		ownerCommitment := gadget.PoseidonHash(api, []frontend.Variable{c.OwnerHashes[i], c.Blindings[i]})
		ciphertextHash := gadget.HashBytes(api, ciphertext[i*OpeningBytes:(i+1)*OpeningBytes])
		chain = append(chain, api.Mul(enabled[i], ownerCommitment), api.Mul(enabled[i], ciphertextHash))
	}
	auditorLo, auditorHi := base.Pack33To2FECircuit(api, auditor)
	ephLo, ephHi := base.Pack33To2FECircuit(api, ephemeral)
	chain = append(chain, auditorLo, auditorHi, ephLo, ephHi)
	// 4. Bind disclosure to the program's SPP deposit bytes.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}

// The plaintext must be the canonical field encoding.
func canonicalBytes(api frontend.API, value frontend.Variable) [32]frontend.Variable {
	bits := api.ToBinary(value, 256)
	var out [32]frontend.Variable
	for i := range out {
		out[31-i] = api.FromBinary(bits[i*8 : (i+1)*8]...)
	}
	return out
}
