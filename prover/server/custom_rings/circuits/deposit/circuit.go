// Package deposit binds every deposited owner's commitment to an opening
// encrypted for the configured auditor.
package deposit

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
	ve "github.com/helius-labs/zolana/prover/server/circuits/encryption"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
)

const MaxDeposits = 8

// One opening is `ownerHash || blinding || ownerKey`. The owner key is the
// Ed25519 key of an anonymous ring deposit and zero otherwise, so the auditor
// attributes an anonymous deposit before it is spent.
const OpeningBytes = 96
const Domain uint32 = 0x43524450 // CRDP
const EncryptionInfo = "CRING/dep1"

// Each owner commitment must match the opening encrypted for the auditor.
type CustomRingDepositCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	ContextHash     frontend.Variable
	Count           frontend.Variable
	Anonymous       frontend.Variable
	OwnerPkHashes   [MaxDeposits]frontend.Variable
	OwnerKeys       [MaxDeposits][32]frontend.Variable
	NullifierPks    [MaxDeposits]frontend.Variable
	Blindings       [MaxDeposits]frontend.Variable
	EphSk           [32]frontend.Variable
	AuditorPk       [32]frontend.Variable
	KeyEscrow       frontend.Variable
	KeyRegistryRoot frontend.Variable
	Keys            [MaxDeposits]registry.KeyOpening
}

func (c *CustomRingDepositCircuit) Define(api frontend.API) error {
	// 1. Prove exactly the occupied prefix with canonical zero padding.
	api.AssertIsBoolean(c.Anonymous)
	var countMatches [MaxDeposits]frontend.Variable
	validCount := frontend.Variable(0)
	for i := range countMatches {
		countMatches[i] = api.IsZero(api.Sub(c.Count, i+1))
		validCount = api.Add(validCount, countMatches[i])
	}
	api.AssertIsEqual(validCount, 1)
	var enabled [MaxDeposits]frontend.Variable
	var ownerHashes [MaxDeposits]frontend.Variable
	plaintext := make([]frontend.Variable, MaxDeposits*OpeningBytes)
	registry.AssertMode(api, c.KeyEscrow, c.KeyRegistryRoot)
	for i := range c.OwnerPkHashes {
		enabled[i] = frontend.Variable(0)
		for _, count := range countMatches[i:] {
			enabled[i] = api.Add(enabled[i], count)
		}
		disabled := api.Sub(1, enabled[i])
		api.AssertIsEqual(api.Mul(disabled, c.OwnerPkHashes[i]), 0)
		api.AssertIsEqual(api.Mul(disabled, c.NullifierPks[i]), 0)
		api.AssertIsEqual(api.Mul(disabled, c.Blindings[i]), 0)
		// An anonymous ring can admit only Ed25519-owned notes. The opening
		// binds the hidden owner key to the deposited owner commitment.
		identity := gadget.SolanaOwnerIdentity(api, c.OwnerKeys[i])
		api.AssertIsEqual(api.Mul(c.Anonymous, enabled[i], api.Sub(c.OwnerPkHashes[i], identity)), 0)
		for _, b := range c.OwnerKeys[i] {
			api.AssertIsEqual(api.Mul(api.Sub(1, api.Mul(c.Anonymous, enabled[i])), b), 0)
		}
		c.Keys[i].AssertEscrowed(api, api.Mul(enabled[i], c.KeyEscrow), c.KeyRegistryRoot, c.OwnerPkHashes[i], c.NullifierPks[i])
		ownerHashes[i] = gadget.PoseidonHash(api, []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i]})
		owner, blinding := canonicalBytes(api, ownerHashes[i]), canonicalBytes(api, c.Blindings[i])
		copy(plaintext[i*OpeningBytes:], owner[:])
		copy(plaintext[i*OpeningBytes+32:], blinding[:])
		copy(plaintext[i*OpeningBytes+64:], c.OwnerKeys[i][:])
	}

	// 2. Bind the shared key to the auditor and published ephemeral key.
	auditor, ephemeral, dh := base.AgreeAuditKey(api, c.EphSk, c.AuditorPk)
	secret := base.DeriveAuditSharedSecret(api, dh, ephemeral, auditor)
	info := make([]frontend.Variable, len(EncryptionInfo))
	for i, b := range []byte(EncryptionInfo) {
		info[i] = b
	}
	key, nonce := ve.KeySchedule(api, secret, info, len(info))

	// 3. Assign distinct CTR blocks to every deposit opening.
	ciphertext := aes.NewCipher(api, key).CTREncrypt(nonce, plaintext)
	chain := []frontend.Variable{Domain, c.ContextHash, c.Count, c.Anonymous}
	for i := range ownerHashes {
		ownerCommitment := gadget.PoseidonHash(api, []frontend.Variable{ownerHashes[i], c.Blindings[i]})
		ciphertextHash := gadget.HashBytes(api, ciphertext[i*OpeningBytes:(i+1)*OpeningBytes])
		chain = append(chain, api.Mul(enabled[i], ownerCommitment), api.Mul(enabled[i], ciphertextHash))
	}
	auditorLo, auditorHi := base.Pack33To2FECircuit(api, auditor)
	ephLo, ephHi := base.Pack33To2FECircuit(api, ephemeral)
	chain = append(chain, auditorLo, auditorHi, ephLo, ephHi, c.KeyEscrow, c.KeyRegistryRoot)
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
