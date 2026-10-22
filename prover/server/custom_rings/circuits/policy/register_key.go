package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// Properties:
// 1. The nullifier key is Poseidon of the 31-byte nullifier secret the envelope seals to
// AuditorPk, so the auditor recovers the secret behind the escrowed key.
// 2. The statement binds the member, the key, both tagged envelope keys and the ciphertext
// hash, and the program queues the escrow write Poseidon(nullifier_pk, ct_hash) from them.
// 3. No registry record and no UTXO owner is opened, the queue applies the write later.

// NfKeyEncInfo separates the key ciphertext from the audit one, mirrored by NF_KEY_ENC_INFO in custom-rings/client/src/encryption.rs.
const NfKeyEncInfo = "CRING/nfk1"

type KeyRegisterCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	Member          frontend.Variable
	NullifierSecret [32]frontend.Variable
	EphSk           [32]frontend.Variable
	AuditorPk       [32]frontend.Variable
}

func (c *KeyRegisterCircuit) Define(api frontend.API) error {
	// 1. A zero lead byte keeps the secret below q, the envelope's cipher bounds the other 31 bytes.
	api.AssertIsEqual(c.NullifierSecret[0], 0)
	nullifierPk := gadget.PoseidonHash(api, gadget.PackBytesBEWith(api, gadget.BoundedBytes{}, c.NullifierSecret[1:]))
	// 2. The envelope seals the same 32 bytes to the auditor, its cipher bounds every ciphertext byte.
	sealed := base.Envelope{Plaintext: c.NullifierSecret[:], EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: NfKeyEncInfo}.Seal(api)
	// 3. The statement names the member and the envelope the program reads from the instruction.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(api, nullifierPk, sealed)))
	return nil
}

// statement is [CRRG, member, nullifier_pk, aud0, aud1, eph0, eph1, ct_hash], rebuilt by the
// program through custom-rings/interface/src/statement.rs.
func (c *KeyRegisterCircuit) statement(api frontend.API, nullifierPk frontend.Variable, sealed base.Sealed) []frontend.Variable {
	return []frontend.Variable{
		base.RegisterKeyDomain, c.Member, nullifierPk, sealed.Auditor[0], sealed.Auditor[1], sealed.Eph[0], sealed.Eph[1],
		gadget.HashBoundedBytes(api, sealed.Ciphertext),
	}
}
