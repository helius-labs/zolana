package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	base "zolana/prover/circuits/custom_ring/base"
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/verifiable-encryption/p256"
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
	LowProof     [HeadMapHeight]frontend.Variable
	NewProof     [HeadMapHeight]frontend.Variable
}

func (c *KeyRegisterCircuit) Define(api frontend.API) error {
	// The emulated P-256 arithmetic does not range-check its bytes.
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

	ctCommitment := gadget.PoseidonHash(api, []frontend.Variable{nullifierPk, sealed.CiphertextHash})
	newRoot := headRegistration{
		oldRoot:  c.HeadOldRoot,
		low:      headLeaf{member: c.LowMember, next: c.LowNext, nullifier: c.LowNullifier},
		lowIndex: c.LowIndex,
		lowProof: c.LowProof[:],
		member:   c.Member,
		genesis:  ctCommitment,
		newIndex: c.NewIndex,
		newProof: c.NewProof[:],
	}.newRoot(api)
	api.AssertIsEqual(newRoot, c.HeadNewRoot)

	chain := []frontend.Variable{
		c.HeadOldRoot, c.HeadNewRoot, c.Member,
		nullifierPk, sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, sealed.CiphertextHash,
		c.NewIndex,
	}
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
