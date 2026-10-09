package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"zolana/prover/circuits/gadget"
	ve "zolana/prover/circuits/verifiable-encryption"
	base "zolana/prover/custom_rings/circuits/base"
	"zolana/prover/custom_rings/circuits/registry"
)

// Separates the nullifier key ciphertext from the audit ciphertext, equals Rust NF_KEY_ENC_INFO.
const NfKeyEncInfo = "CRING/nfk1"

// Attests the member's own key claim, unbound to any UTXO owner.
type KeyRegisterCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	RegistryOldRoot frontend.Variable
	RegistryNewRoot frontend.Variable
	Member          frontend.Variable
	NewIndex        frontend.Variable

	// Byte 0 is zero, the 31-byte packing stays below the field order.
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
	// 1. Bound all bytes and limit the nullifier secret to 31 bytes.
	rangeChecker := rangecheck.New(api)
	for _, b := range c.NullifierSecret {
		rangeChecker.Check(b, 8)
	}
	api.AssertIsEqual(c.NullifierSecret[0], 0)

	// 2. Bind the encrypted secret to the registered nullifier public key.
	secretFE := gadget.BytesToField(api, c.NullifierSecret[:])
	nullifierPk := gadget.PoseidonHash(api, []frontend.Variable{secretFE})

	encrypted := ve.Envelope{
		SecretTag:   base.SharedSecretTag,
		KdfInfo:     []byte(NfKeyEncInfo),
		EphemeralSk: c.EphSk,
		RecipientPk: c.AuditorPk,
		Plaintext:   c.NullifierSecret[:],
	}.Encrypt(api)
	ciphertextHash := gadget.HashBytes(api, encrypted.Ciphertext)

	// 3. Require member absence before inserting the key hash.
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

	// 4. Bind registration to the program's public statement.
	chain := []frontend.Variable{
		c.RegistryOldRoot, c.RegistryNewRoot, c.Member,
		nullifierPk, encrypted.RecipientLo, encrypted.RecipientHi, encrypted.EphemeralLo, encrypted.EphemeralHi, ciphertextHash,
		c.NewIndex,
	}
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
