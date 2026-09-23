package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/verifiable-encryption/p256"
	base "zolana/prover/custom_rings/circuits/base"
	"zolana/prover/custom_rings/circuits/registry"
)

// Separates the nullifier key ciphertext from the audit ciphertext, equals Rust NF_KEY_ENC_INFO.
const NfKeyEncInfo = "CRING/nfk1"

// Attests the member's own key claim, unbound to any UTXO owner.
type KeyRegisterCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	HeadOldRoot frontend.Variable
	HeadNewRoot frontend.Variable
	Member      frontend.Variable
	NewIndex    frontend.Variable

	// Byte 0 is zero, the 31-byte packing stays below the field order.
	NullifierSecret [32]frontend.Variable
	EphSk           [32]frontend.Variable
	AuditorPk       [65]frontend.Variable

	LowMember    frontend.Variable
	LowNext      frontend.Variable
	LowNullifier frontend.Variable
	LowIndex     frontend.Variable
	LowProof     [registry.Height]frontend.Variable
	NewProof     [registry.Height]frontend.Variable
}

func (c *KeyRegisterCircuit) Define(api frontend.API) error {
	// 1. Bound all bytes and limit the nullifier secret to 31 bytes.
	rangeChecker := rangecheck.New(api)
	for _, b := range c.NullifierSecret {
		rangeChecker.Check(b, 8)
	}
	for _, b := range c.EphSk {
		rangeChecker.Check(b, 8)
	}
	for _, b := range c.AuditorPk {
		rangeChecker.Check(b, 8)
	}
	api.AssertIsEqual(c.AuditorPk[0], 4)
	api.AssertIsEqual(c.NullifierSecret[0], 0)
	p256.PointOnCurve(api, c.AuditorPk)

	// 2. Bind the encrypted secret to the registered nullifier public key.
	secretFE := frontend.Variable(0)
	for _, b := range c.NullifierSecret {
		secretFE = api.Add(api.Mul(secretFE, 256), b)
	}
	nullifierPk := gadget.PoseidonHash(api, []frontend.Variable{secretFE})

	sealed := base.Envelope{
		Plaintext: c.NullifierSecret,
		EphSk:     c.EphSk,
		AuditorPk: c.AuditorPk,
		Info:      NfKeyEncInfo,
	}.Seal(api)

	// 3. Require member absence before inserting the ciphertext commitment.
	ctCommitment := gadget.PoseidonHash(api, []frontend.Variable{nullifierPk, sealed.CiphertextHash})
	newRoot := registry.Insertion{
		OldRoot:  c.HeadOldRoot,
		Low:      registry.Leaf{Member: c.LowMember, Next: c.LowNext, Key: c.LowNullifier},
		LowIndex: c.LowIndex,
		LowProof: c.LowProof[:],
		Member:   c.Member,
		Key:      ctCommitment,
		NewIndex: c.NewIndex,
		NewProof: c.NewProof[:],
	}.NewRoot(api)
	api.AssertIsEqual(newRoot, c.HeadNewRoot)

	// 4. Bind registration to the program's public statement.
	chain := []frontend.Variable{
		c.HeadOldRoot, c.HeadNewRoot, c.Member,
		nullifierPk, sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, sealed.CiphertextHash,
		c.NewIndex,
	}
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
