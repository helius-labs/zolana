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

// Properties: the member's absence from the registry and the insertion of Poseidon(nullifier_pk, ct_hash),
// where the nullifier secret is AES-CTR encrypted to AuditorPk. No UTXO owner is bound.

type KeyRegisterCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	RegistryOldRoot frontend.Variable
	RegistryNewRoot frontend.Variable
	Member          frontend.Variable
	NewIndex        frontend.Variable

	// A zero byte 0 keeps the secret below the field order.
	NullifierSecret [32]frontend.Variable
	EphSk           [32]frontend.Variable
	AuditorPk       [65]frontend.Variable

	LowMember frontend.Variable
	LowNext   frontend.Variable
	LowKey    frontend.Variable
	LowIndex  frontend.Variable
	LowProof  [registry.Height]frontend.Variable
	NewProof  [registry.Height]frontend.Variable
}

func (c *KeyRegisterCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	base.CheckBytes(rc, c.NullifierSecret[:])
	api.AssertIsEqual(c.NullifierSecret[0], 0)
	nullifierPk := gadget.PoseidonHash(api, gadget.PackBytesBE(api, c.NullifierSecret[1:]))
	sealed := base.Envelope{Plaintext: c.NullifierSecret[:], EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: NfKeyEncInfo}.Seal(api, rc)
	ctHash := gadget.HashBytes(api, sealed.Ciphertext)
	newRoot := registry.Insertion{
		OldRoot:  c.RegistryOldRoot,
		Low:      registry.Leaf{Member: c.LowMember, Next: c.LowNext, Key: c.LowKey},
		LowIndex: c.LowIndex,
		LowProof: c.LowProof[:],
		Member:   c.Member,
		Key:      gadget.PoseidonHash(api, []frontend.Variable{nullifierPk, ctHash}),
		NewIndex: c.NewIndex,
		NewProof: c.NewProof[:],
	}.NewRoot(api)
	api.AssertIsEqual(newRoot, c.RegistryNewRoot)
	chain := slices.Concat([]frontend.Variable{c.RegistryOldRoot, c.RegistryNewRoot, c.Member, nullifierPk}, sealed.Auditor, sealed.Eph, []frontend.Variable{ctHash, c.NewIndex})
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
