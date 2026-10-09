// Package base holds the base circuit of the custom ring
// program. It proves that the per-transaction viewing secret key of an SPP
// transaction is verifiably encrypted to the ring's auditor public key, and that
// the transaction's published viewing public key really is that secret's public
// key.
//
// The circuit has exactly one public input, PublicInputHash, the Poseidon hash
// chain over these eleven elements in this exact order:
//
//  1. private_tx_hash    -- pass-through, not recomputed here
//  2. tx_viewing_pk_lo   -- packed compressed tx_viewing_sk * G
//  3. tx_viewing_pk_hi
//  4. auditor_pk_lo      -- packed compressed witnessed auditor key
//  5. auditor_pk_hi
//  6. eph_pk_lo          -- packed compressed eph_sk * G
//  7. eph_pk_hi
//  8. ct_hash            -- Poseidon commitment of the 32-byte ciphertext
//  9. output_hash_chain   -- SPP commitments for the published output prefix
//  10. salt               -- transaction salt used by the disclosure stream
//  11. disclosure_hash    -- encrypted output commitment fields
//
// The on-chain Rust recompute in
// custom-rings/interface/src/base_public_input.rs
// (CustomRingBasePublicInput::hash) MUST mirror this chain order element for element:
// gadget.HashChain here == zolana_hasher::hash_chain::create_hash_chain_from_slice
// there, gadget.HashBytes here == zolana_hasher::primitives::hash_bytes
// (== zolana_interface::merge_utils::ciphertext_hash::<32>) there, and the
// packing of elements 2..7 is defined by packCompressedPoint in
// circuits/verifiable-encryption/p256/keyagreement.go.
package base

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"zolana/prover/circuits/gadget"
	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/circuits/verifiable-encryption/p256"
)

// AuditEncInfo is the key-schedule info string. It MUST equal the Rust
// AUDIT_ENC_INFO constant byte for byte.
const AuditEncInfo = "CRING/adt1"

// SharedSecretTag is the shared-secret domain separator "CR_S", the first
// Poseidon input of the envelope shared secret. The Rust host derivation
// (DOM_SEP_CR_SHARED in custom-rings/client/src/encryption.rs) MUST use the
// same value.
var SharedSecretTag = []byte("CR_S")

// CustomRingBaseCircuit is the audit-only custom-ring proof.
//
// Both scalars are witnessed as 32 big-endian bytes and the auditor key as the
// 65-byte uncompressed SEC1 point, because that is what the p256 gadgets
// consume and what the witness assigner supports.
type CustomRingBaseCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	// PrivateTxHash is the SPP transaction hash, folded into the public input
	// chain unchanged so the on-chain program can bind this proof to the
	// transaction it accompanies.
	PrivateTxHash frontend.Variable

	// TxViewingSk is the transaction viewing scalar, big-endian. It is both the
	// AES plaintext and the scalar whose public key is chain elements 2 and 3.
	TxViewingSk [32]frontend.Variable

	// EphSk is a fresh ephemeral scalar, big-endian. Encrypting under an
	// ephemeral key keeps the encryption out of the key-dependent-message
	// setting that ECDH(TxViewingSk, AuditorPk) would create.
	EphSk [32]frontend.Variable

	// AuditorPk is the auditor key as 0x04 || x || y.
	AuditorPk           [65]frontend.Variable
	Salt                [16]frontend.Variable
	Outputs             [AuditOutputSlots]AuditOutputWires
	OutputCountSelected [AuditOutputSlots]frontend.Variable
}

// AuditBlockWires carries the audit block's witnesses into a folding circuit.
type AuditBlockWires struct {
	PrivateTxHash       frontend.Variable
	TxViewingSk         [32]frontend.Variable
	EphSk               [32]frontend.Variable
	AuditorPk           [65]frontend.Variable
	Salt                [16]frontend.Variable
	Outputs             [AuditOutputSlots]AuditOutputWires
	OutputCountSelected [AuditOutputSlots]frontend.Variable
}

func (c *CustomRingBaseCircuit) Define(api frontend.API) error {
	elements, _ := DefineAuditBlock(api, AuditBlockWires{
		PrivateTxHash:       c.PrivateTxHash,
		TxViewingSk:         c.TxViewingSk,
		EphSk:               c.EphSk,
		AuditorPk:           c.AuditorPk,
		Salt:                c.Salt,
		Outputs:             c.Outputs,
		OutputCountSelected: c.OutputCountSelected,
	})

	// The single public input, chain order pinned by the package comment.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, elements[:]))
	return nil
}

// DefineAuditBlock constrains the audit statement and returns its chain
// elements. It also returns the transaction viewing key it derived, so a
// later block can agree a key with it without a second base multiplication.
func DefineAuditBlock(api frontend.API, w AuditBlockWires) ([11]frontend.Variable, p256.PublicKey) {
	// Chain elements 2 and 3. This is the binding that the transaction's
	// published tx_viewing_pk equals TxViewingSk * G, which is what makes the
	// ciphertext below worth anything.
	txViewingKey := p256.DerivePublicKey(api, w.TxViewingSk)
	txLo, txHi := txViewingKey.Packed(api)

	// Chain elements 4 to 7: the auditor key the program reads from its config
	// account and the ephemeral key that rides in the message data, so the
	// auditor can rederive the shared secret. The envelope never trusts the
	// witnessed auditor point: an off-curve key would make the ECDH output
	// attacker-chosen.
	encrypted := ve.Envelope{
		SecretTag:   SharedSecretTag,
		KdfInfo:     []byte(AuditEncInfo),
		EphemeralSk: w.EphSk,
		RecipientPk: w.AuditorPk,
		Plaintext:   w.TxViewingSk[:],
	}.Encrypt(api)
	// Chain element 8. Ciphertext integrity comes from this hash, not from a
	// GCM tag.
	ciphertextHash := gadget.HashBytes(api, encrypted.Ciphertext)
	outputHashChain, disclosureHash := disclosureElements(
		api, rangecheck.New(api), w.TxViewingSk, w.Salt, w.Outputs, w.OutputCountSelected,
	)
	saltField := gadget.PackBytesBE(api, w.Salt[:])[0]

	return [11]frontend.Variable{
		w.PrivateTxHash,
		txLo, txHi,
		encrypted.RecipientLo, encrypted.RecipientHi,
		encrypted.EphemeralLo, encrypted.EphemeralHi,
		ciphertextHash,
		outputHashChain,
		saltField,
		disclosureHash,
	}, txViewingKey
}
