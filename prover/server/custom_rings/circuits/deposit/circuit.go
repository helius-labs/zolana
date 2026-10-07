package deposit

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/custom_rings/circuits/base"
	"zolana/prover/custom_rings/circuits/registry"
)

const MaxDeposits = 8
const DepositPlaintextBytes = 64
const Domain uint32 = 0x43524450
const EncryptionInfo = "CRING/dep1"

type CustomRingDepositCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	ContextHash     frontend.Variable
	Count           frontend.Variable
	OwnerPkHashes   [MaxDeposits]frontend.Variable
	NullifierPks    [MaxDeposits]frontend.Variable
	Blindings       [MaxDeposits]frontend.Variable
	EphSk           [32]frontend.Variable
	AuditorPk       [65]frontend.Variable
	KeyEscrow       frontend.Variable
	KeyRegistryRoot frontend.Variable
	Keys            [MaxDeposits]registry.KeyOpening
}

func (c *CustomRingDepositCircuit) Define(api frontend.API) error {
	var countMatches [MaxDeposits]frontend.Variable
	validCount := frontend.Variable(0)
	for i := range countMatches {
		countMatches[i] = api.IsZero(api.Sub(c.Count, i+1))
		validCount = api.Add(validCount, countMatches[i])
	}
	api.AssertIsEqual(validCount, 1)
	var enabled [MaxDeposits]frontend.Variable
	var ownerHashes [MaxDeposits]frontend.Variable
	plaintext := make([]frontend.Variable, MaxDeposits*DepositPlaintextBytes)
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
		c.Keys[i].AssertEscrowed(api, api.Mul(enabled[i], c.KeyEscrow), c.KeyRegistryRoot, c.OwnerPkHashes[i], c.NullifierPks[i])
		ownerHashes[i] = gadget.PoseidonHash(api, []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i]})
		copy(plaintext[i*DepositPlaintextBytes:], ve.FieldToBytesBE(api, ownerHashes[i], 32))
		copy(plaintext[i*DepositPlaintextBytes+32:], ve.FieldToBytesBE(api, c.Blindings[i], 32))
	}

	encrypted := ve.Envelope{
		SecretTag:   base.SharedSecretTag,
		KdfInfo:     []byte(EncryptionInfo),
		EphemeralSk: c.EphSk,
		RecipientPk: c.AuditorPk,
		Plaintext:   plaintext,
	}.Encrypt(api)
	chain := []frontend.Variable{Domain, c.ContextHash, c.Count}
	for i := range ownerHashes {
		ownerCommitment := gadget.PoseidonHash(api, []frontend.Variable{ownerHashes[i], c.Blindings[i]})
		ciphertextHash := gadget.HashBytes(api, encrypted.Ciphertext[i*DepositPlaintextBytes:(i+1)*DepositPlaintextBytes])
		chain = append(chain, api.Mul(enabled[i], ownerCommitment), api.Mul(enabled[i], ciphertextHash))
	}
	chain = append(chain, encrypted.RecipientLo, encrypted.RecipientHi, encrypted.EphemeralLo, encrypted.EphemeralHi, c.KeyEscrow, c.KeyRegistryRoot)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
