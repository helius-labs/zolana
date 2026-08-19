// Package auditor_key_encryption holds the single circuit of the minimal custom
// ring example: it proves that the per-transaction viewing secret key of an SPP
// transaction is verifiably encrypted to the ring's auditor public key, and that
// the transaction's published viewing public key really is that secret's public
// key.
//
// The circuit has exactly one public input, PublicInputHash, the Poseidon hash
// chain over these eight elements in this exact order:
//
//  1. private_tx_hash    -- pass-through, not recomputed here
//  2. tx_viewing_pk_lo   -- packed compressed tx_viewing_sk * G
//  3. tx_viewing_pk_hi
//  4. auditor_pk_lo      -- packed compressed witnessed auditor key
//  5. auditor_pk_hi
//  6. eph_pk_lo          -- packed compressed eph_sk * G
//  7. eph_pk_hi
//  8. ct_hash            -- Poseidon commitment of the 32-byte ciphertext
//
// The on-chain Rust recompute in
// custom-rings/program/src/instructions/transact.rs
// (AuditPublicInput::hash) MUST mirror this chain order element for element:
// gadget.HashChain here == zolana_hasher::hash_chain::create_hash_chain_from_slice
// there, gadget.HashBytes here == zolana_hasher::primitives::hash_bytes
// (== zolana_interface::merge_utils::ciphertext_hash::<32>) there, and the
// packing of elements 2..7 is defined by pack.go. Every comment step below is
// tagged with the chain element(s) it produces.
package auditor_key_encryption

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"zolana/prover/circuits/gadget"
	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/circuits/verifiable-encryption/aes"
	"zolana/prover/circuits/verifiable-encryption/p256"
)

// auditEncInfo is the key-schedule info string. It MUST equal the Rust
// AUDIT_ENC_INFO constant byte for byte.
var auditEncInfo = []byte("CRING/adt1")

// Circuit is the auditor key encryption proof.
//
// Both scalars are witnessed as 32 big-endian bytes and the auditor key as the
// 65-byte uncompressed SEC1 point, because that is what the p256 gadgets
// consume and what the witness assigner supports. Every one of those 129 bytes
// is range-checked in Define: p256's byte-to-limb conversion does not
// range-check, so unconstrained bytes would let a prover feed unnormalized
// limbs into the emulated field.
type Circuit struct {
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
	AuditorPk [65]frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	// (a) Range-check all 129 witnessed bytes to 8 bits. rangecheck.New reuses
	// the range checker the emulated P-256 arithmetic already instantiates, so
	// these checks share its lookup table.
	checker := rangecheck.New(api)
	for _, b := range c.TxViewingSk {
		checker.Check(b, 8)
	}
	for _, b := range c.EphSk {
		checker.Check(b, 8)
	}
	for _, b := range c.AuditorPk {
		checker.Check(b, 8)
	}
	// The p256 compression gadget derives the SEC1 prefix from the y parity and
	// ignores byte 0, so the uncompressed prefix has to be constrained here.
	api.AssertIsEqual(c.AuditorPk[0], 4)

	// (b) Never trust a witnessed point: an off-curve auditor key would make the
	// ECDH output attacker-chosen.
	p256.PointOnCurve(api, c.AuditorPk)

	// (c) Chain elements 2 and 3. This is the binding that the transaction's
	// published tx_viewing_pk equals TxViewingSk * G, which is what makes the
	// ciphertext below worth anything.
	txCompressed := p256.CompressPubkey(api, p256.ScalarMulGenerator(api, c.TxViewingSk))
	txLo, txHi := Pack33To2FECircuit(api, txCompressed)

	// (d) Chain elements 4 and 5: the auditor key the program reads from its
	// config account.
	auditorCompressed := p256.CompressPubkey(api, c.AuditorPk)
	auditorLo, auditorHi := Pack33To2FECircuit(api, auditorCompressed)

	// (e) Chain elements 6 and 7: the ephemeral key that rides in the message
	// data, so the auditor can rederive the shared secret.
	ephCompressed := p256.CompressPubkey(api, p256.ScalarMulGenerator(api, c.EphSk))
	ephLo, ephHi := Pack33To2FECircuit(api, ephCompressed)

	// (f) ECDH: the 32-byte big-endian x-coordinate of EphSk * AuditorPk.
	dh := p256.ECDH(api, c.EphSk, c.AuditorPk)

	// (g) Bind the raw ECDH output to both public keys (see pack.go).
	sharedSecret := DeriveAuditSharedSecret(api, dh, ephCompressed, auditorCompressed)

	// (h) Poseidon key schedule, mirroring the Rust host KDF
	// (zolana_keypair::symmetric_apply with the same info string).
	key, nonce := ve.KeySchedule(api, sharedSecret, auditEncInfoVars(), len(auditEncInfo))

	// (i) AES-256-CTR over the 32-byte plaintext scalar. Ciphertext integrity
	// comes from the hash in (j), not from a GCM tag.
	ciphertext := aes.CTREncrypt(api, aes.NewAESGadget(api), key, nonce, c.TxViewingSk[:])

	// (j) Chain element 8.
	ciphertextHash := gadget.HashBytes(api, ciphertext)

	// (k) The single public input, chain order pinned by the package comment.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, []frontend.Variable{
		c.PrivateTxHash,
		txLo, txHi,
		auditorLo, auditorHi,
		ephLo, ephHi,
		ciphertextHash,
	}))
	return nil
}

func auditEncInfoVars() []frontend.Variable {
	out := make([]frontend.Variable, len(auditEncInfo))
	for i, b := range auditEncInfo {
		out[i] = frontend.Variable(b)
	}
	return out
}
