// Package deposit binds every deposited owner commitment to an opening encrypted for the auditor.
package deposit

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	checked "github.com/helius-labs/zolana/prover/server/circuits/gadget/v2"
	ve "github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
)

const (
	MaxDeposits = 8
	// OpeningBytes is owner hash || blinding || owner key.
	OpeningBytes   = 96
	Domain         = 0x43524450 // "CRDP"
	EncryptionInfo = "CRING/dep1"
)

// Properties: the first Count of 1..8 owner commitments open to (owner hash, blinding, Ed25519 owner key in an
// anonymous ring else zero) AES-CTR encrypted to AuditorPk, padding slots are zero, escrow finds every owner's key.

type CustomRingDepositCircuit struct {
	PublicInputHash    frontend.Variable `gnark:",public"`
	ContextHash        frontend.Variable
	Count              frontend.Variable
	Anonymous          frontend.Variable
	OwnerPkHashes      [MaxDeposits]frontend.Variable
	OwnerKeys          [MaxDeposits][32]frontend.Variable
	NullifierPks       [MaxDeposits]frontend.Variable
	Blindings          [MaxDeposits]frontend.Variable
	EphSk              [32]frontend.Variable
	AuditorPk          [32]frontend.Variable
	KeyEscrow          frontend.Variable
	MemberRegistryRoot frontend.Variable
	CtHashes           [MaxDeposits]frontend.Variable
	Members            [MaxDeposits]registry.RecordOpening
}

func (c *CustomRingDepositCircuit) Define(api frontend.API) error {
	api.AssertIsBoolean(c.Anonymous)
	count := base.SelectCount(api, c.Count, 1, MaxDeposits)
	registry.AssertMode(api, c.KeyEscrow, c.MemberRegistryRoot)
	owners := make([]frontend.Variable, MaxDeposits)
	var plaintext []frontend.Variable
	for i := range owners {
		padding := api.Sub(1, count.Active[i])
		for _, value := range []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i], c.Blindings[i]} {
			api.AssertIsEqual(api.Mul(padding, value), 0)
		}
		escrowed := api.Mul(count.Active[i], c.KeyEscrow)
		c.Members[i].AssertPresent(api, escrowed, c.MemberRegistryRoot, c.OwnerPkHashes[i])
		key := gadget.PoseidonHash(api, []frontend.Variable{c.NullifierPks[i], c.CtHashes[i]})
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: escrowed, A: c.Members[i].EscrowKey, B: key})
		anonymous := api.Mul(c.Anonymous, count.Active[i])
		// SolanaOwnerIdentity bounds the key bytes the envelope encrypts.
		identity := checked.SolanaOwnerIdentity(api, c.OwnerKeys[i])
		api.AssertIsEqual(api.Mul(anonymous, api.Sub(c.OwnerPkHashes[i], identity)), 0)
		for _, b := range c.OwnerKeys[i] {
			api.AssertIsEqual(api.Mul(api.Sub(1, anonymous), b), 0)
		}
		owners[i] = gadget.PoseidonHash(api, []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i]})
		// The canonical field encoding keeps one plaintext per opening.
		plaintext = slices.Concat(plaintext, ve.FieldToBytesBE(api, owners[i], 32), ve.FieldToBytesBE(api, c.Blindings[i], 32), c.OwnerKeys[i][:])
	}
	sealed := base.Envelope{Plaintext: plaintext, EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: EncryptionInfo}.Seal(api)
	chain := []frontend.Variable{Domain, c.ContextHash, c.Count, c.Anonymous}
	for i, owner := range owners {
		commitment := gadget.PoseidonHash(api, []frontend.Variable{owner, c.Blindings[i]})
		ciphertext := gadget.HashBytes(api, sealed.Ciphertext[i*OpeningBytes:(i+1)*OpeningBytes])
		chain = append(chain, api.Mul(count.Active[i], commitment), api.Mul(count.Active[i], ciphertext))
	}
	chain = slices.Concat(chain, sealed.Auditor, sealed.Eph, []frontend.Variable{c.KeyEscrow, c.MemberRegistryRoot})
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
