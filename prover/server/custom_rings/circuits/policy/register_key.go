package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"zolana/prover/circuits/gadget"
	ve "zolana/prover/circuits/verifiable-encryption"
	base "zolana/prover/custom_rings/circuits/base"
	"zolana/prover/custom_rings/circuits/registry"
)

const NfKeyEncInfo = "CRING/nfk1"

type KeyRegisterCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	RegistryOldRoot frontend.Variable
	RegistryNewRoot frontend.Variable
	Member          frontend.Variable
	NewIndex        frontend.Variable

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
	rangeChecker := rangecheck.New(api)
	for _, b := range c.NullifierSecret {
		rangeChecker.Check(b, 8)
	}
	for _, b := range c.EphSk {
		rangeChecker.Check(b, 8)
	}
	api.AssertIsEqual(c.NullifierSecret[0], 0)

	secretFE := ve.BytesToField(api, c.NullifierSecret[:])
	nullifierPk := gadget.PoseidonHash(api, []frontend.Variable{secretFE})

	sealed := ve.Envelope{
		SecretTag:   base.SharedSecretTag,
		KdfInfo:     []byte(NfKeyEncInfo),
		EphemeralSk: c.EphSk,
		RecipientPk: c.AuditorPk,
		Plaintext:   c.NullifierSecret[:],
	}.Seal(api)
	ciphertextHash := gadget.HashBytes(api, sealed.Ciphertext)

	keyHash := gadget.PoseidonHash(api, []frontend.Variable{nullifierPk, ciphertextHash})
	newRoot := registry.Insertion{
		OldRoot:  c.RegistryOldRoot,
		Low:      registry.Leaf{Member: c.LowMember, Next: c.LowNext, Key: c.LowKey},
		LowIndex: c.LowIndex,
		LowProof: c.LowProof[:],
		Member:   c.Member,
		Key:      keyHash,
		NewIndex: c.NewIndex,
		NewProof: c.NewProof[:],
	}.NewRoot(api)
	api.AssertIsEqual(newRoot, c.RegistryNewRoot)

	chain := []frontend.Variable{
		c.RegistryOldRoot, c.RegistryNewRoot, c.Member,
		nullifierPk, sealed.RecipientLo, sealed.RecipientHi, sealed.EphemeralLo, sealed.EphemeralHi, ciphertextHash,
		c.NewIndex,
	}
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
