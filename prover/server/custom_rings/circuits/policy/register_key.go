package policy

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
)

// NfKeyEncInfo equals the Rust NF_KEY_ENC_INFO, it separates the key ciphertext from the audit one.
const NfKeyEncInfo = "CRING/nfk1"

// Properties: the member's record gains Poseidon(nullifier_pk, ct_hash) as its escrow key, keeping its
// lists, where the nullifier secret is AES-CTR encrypted to the X25519 key AuditorPk. A member without a
// record is inserted with no lists. No UTXO owner is bound.

type KeyRegisterCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	RegistryOldRoot frontend.Variable
	RegistryNewRoot frontend.Variable
	Member          frontend.Variable
	Lists           frontend.Variable
	registry.RecordUpdate

	// A zero byte 0 keeps the secret below the field order.
	NullifierSecret [32]frontend.Variable
	EphSk           [32]frontend.Variable
	AuditorPk       [32]frontend.Variable
}

func (c *KeyRegisterCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	base.CheckBytes(rc, c.NullifierSecret[:])
	api.AssertIsEqual(c.NullifierSecret[0], 0)
	rc.Check(c.Lists, registry.ListBits)
	nullifierPk := gadget.PoseidonHash(api, gadget.PackBytesBE(api, c.NullifierSecret[1:]))
	sealed := base.Envelope{Plaintext: c.NullifierSecret[:], EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: NfKeyEncInfo}.Seal(api)
	ctHash := gadget.HashBytes(api, sealed.Ciphertext)
	escrowKey := gadget.PoseidonHash(api, []frontend.Variable{nullifierPk, ctHash})
	// The record had no key, a registered key is never overwritten.
	before := registry.Record{Member: c.Member, Next: c.Next, Lists: c.Lists, EscrowKey: 0}
	after := registry.Record{Member: c.Member, Next: c.Next, Lists: c.Lists, EscrowKey: escrowKey}
	api.AssertIsEqual(c.RecordUpdate.Apply(api, 1, c.RegistryOldRoot, before, after), c.RegistryNewRoot)
	chain := slices.Concat([]frontend.Variable{c.RegistryOldRoot, c.RegistryNewRoot, c.Member, nullifierPk}, sealed.Auditor, sealed.Eph, []frontend.Variable{ctHash, c.Index})
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
