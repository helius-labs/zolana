// Package deposit binds every deposited owner commitment to an opening encrypted for the auditor.
package deposit

import (
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	ve "github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
)

const (
	MaxDeposits    = 8
	OpeningBytes   = 64
	Domain         = 0x43524450 // "CRDP"
	EncryptionInfo = "CRING/dep1"
)

// Properties: the first Count of 1..8 owner commitments open to (owner hash, blinding) pairs that are AES-CTR
// encrypted to the X25519 key AuditorPk, padding slots are zero, and escrow puts every owner key in the registry.

type CustomRingDepositCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	ContextHash     frontend.Variable
	Count           frontend.Variable
	OwnerPkHashes   [MaxDeposits]frontend.Variable
	NullifierPks    [MaxDeposits]frontend.Variable
	Blindings       [MaxDeposits]frontend.Variable
	EphSk           [32]frontend.Variable
	AuditorPk       [32]frontend.Variable
	KeyEscrow       frontend.Variable
	KeyRegistryRoot frontend.Variable
	Keys            [MaxDeposits]registry.KeyOpening
}

func (c *CustomRingDepositCircuit) Define(api frontend.API) error {
	count := base.SelectCount(api, c.Count, 1, MaxDeposits)
	registry.AssertMode(api, c.KeyEscrow, c.KeyRegistryRoot)
	owners := make([]frontend.Variable, MaxDeposits)
	var plaintext []frontend.Variable
	for i := range owners {
		padding := api.Sub(1, count.Active[i])
		for _, value := range []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i], c.Blindings[i]} {
			api.AssertIsEqual(api.Mul(padding, value), 0)
		}
		c.Keys[i].AssertEscrowed(api, api.Mul(count.Active[i], c.KeyEscrow), c.KeyRegistryRoot, c.OwnerPkHashes[i], c.NullifierPks[i])
		owners[i] = gadget.PoseidonHash(api, []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i]})
		// The canonical field encoding keeps one plaintext per opening.
		plaintext = slices.Concat(plaintext, ve.FieldToBytesBE(api, owners[i], 32), ve.FieldToBytesBE(api, c.Blindings[i], 32))
	}
	sealed := base.Envelope{Plaintext: plaintext, EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: EncryptionInfo}.Seal(api)
	chain := []frontend.Variable{Domain, c.ContextHash, c.Count}
	for i, owner := range owners {
		commitment := gadget.PoseidonHash(api, []frontend.Variable{owner, c.Blindings[i]})
		ciphertext := gadget.HashBytes(api, sealed.Ciphertext[i*OpeningBytes:(i+1)*OpeningBytes])
		chain = append(chain, api.Mul(count.Active[i], commitment), api.Mul(count.Active[i], ciphertext))
	}
	chain = slices.Concat(chain, sealed.Auditor, sealed.Eph, []frontend.Variable{c.KeyEscrow, c.KeyRegistryRoot})
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
