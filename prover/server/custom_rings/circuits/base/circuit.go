// Package base holds the base circuit of the custom ring
// program. It proves that the per-transaction viewing secret key of an SPP
// transaction is verifiably encrypted to the ring's auditor public key, and that
// the transaction's published viewing public key really is that secret's public
// key.
//
// The circuit has exactly one public input, PublicInputHash, the Poseidon hash
// chain over these twelve elements in this exact order:
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
//  12. anonymous          -- ring mode, selecting full spend disclosure
//
// The on-chain Rust recompute in
// custom-rings/program/src/instructions/transact.rs
// (CustomRingBasePublicInput::hash) MUST mirror this chain order element for element:
// gadget.HashChain here == zolana_hasher::hash_chain::create_hash_chain_from_slice
// there, gadget.HashBytes here == zolana_hasher::primitives::hash_bytes
// (== zolana_interface::merge_utils::ciphertext_hash::<32>) there, and the
// packing of elements 2..7 is defined by pack.go. Every comment step below is
// tagged with the chain element(s) it produces.
package base

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/p256"
	ve "github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/aes"
)

// auditEncInfo is the key-schedule info string. It MUST equal the Rust
// AUDIT_ENC_INFO constant byte for byte.
const auditEncInfo = "CRING/adt1"

// CustomRingBaseCircuit is the audit-only custom-ring proof.
//
// TxViewingSk retains its P-256 big-endian encoding. EphSk and AuditorPk
// are RFC 7748 byte strings; the envelope owns their validation.
type CustomRingBaseCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Anonymous       frontend.Variable

	// PrivateTxHash is the SPP transaction hash, folded into the public input
	// chain unchanged so the on-chain program can bind this proof to the
	// transaction it accompanies.
	PrivateTxHash frontend.Variable

	// TxViewingSk is the transaction viewing scalar, big-endian. It is both the
	// AES plaintext and the scalar whose public key is chain elements 2 and 3.
	TxViewingSk [32]frontend.Variable

	// EphSk is a fresh X25519 secret byte string. Encrypting under an
	// ephemeral key keeps the encryption out of the key-dependent-message
	// setting that ECDH(TxViewingSk, AuditorPk) would create.
	EphSk [32]frontend.Variable

	// AuditorPk is the canonical 32-byte little-endian X25519 coordinate.
	AuditorPk           [32]frontend.Variable
	Salt                [16]frontend.Variable
	Outputs             [AuditOutputSlots]AuditOutputWires
	OutputCountSelected [AuditOutputSlots]frontend.Variable
	Sender              AuditIdentityWires
	Inputs              [AuditInputSlots]AuditUtxoWires
	InputCountSelected  [AuditInputSlots + 1]frontend.Variable
	AnonymousOutputs    [AuditOutputSlots]AuditUtxoWires
	Recipients          [AuditOutputSlots]AuditIdentityWires
	PrivateTxBlinding   frontend.Variable
}

// AuditBlockWires carries the audit block's witnesses into a folding circuit.
type AuditBlockWires struct {
	PrivateTxHash       frontend.Variable
	Anonymous           frontend.Variable
	TxViewingSk         [32]frontend.Variable
	EphSk               [32]frontend.Variable
	AuditorPk           [32]frontend.Variable
	Salt                [16]frontend.Variable
	Outputs             [AuditOutputSlots]AuditOutputWires
	OutputCountSelected [AuditOutputSlots]frontend.Variable
	Sender              AuditIdentityWires
	Inputs              [AuditInputSlots]AuditUtxoWires
	InputCountSelected  [AuditInputSlots + 1]frontend.Variable
	AnonymousOutputs    [AuditOutputSlots]AuditUtxoWires
	Recipients          [AuditOutputSlots]AuditIdentityWires
	PrivateTxBlinding   frontend.Variable
}

func (c *CustomRingBaseCircuit) Define(api frontend.API) error {
	elements := DefineAuditBlock(api, AuditBlockWires{
		PrivateTxHash:       c.PrivateTxHash,
		Anonymous:           c.Anonymous,
		TxViewingSk:         c.TxViewingSk,
		EphSk:               c.EphSk,
		AuditorPk:           c.AuditorPk,
		Salt:                c.Salt,
		Outputs:             c.Outputs,
		OutputCountSelected: c.OutputCountSelected,
		Sender:              c.Sender,
		Inputs:              c.Inputs,
		InputCountSelected:  c.InputCountSelected,
		AnonymousOutputs:    c.AnonymousOutputs,
		Recipients:          c.Recipients,
		PrivateTxBlinding:   c.PrivateTxBlinding,
	})

	// (k) The single public input, chain order pinned by the package comment.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, elements[:]))
	return nil
}

// DefineAuditBlock constrains the audit statement and returns its chain elements.
func DefineAuditBlock(api frontend.API, w AuditBlockWires) [12]frontend.Variable {
	api.AssertIsBoolean(w.Anonymous)
	w.InputCountSelected[0] = api.Sub(1, w.Anonymous)
	// (a) P-256 viewing-key binding still needs its plaintext byte bounds.
	rangeChecker := rangecheck.New(api)
	for _, b := range w.TxViewingSk {
		rangeChecker.Check(b, 8)
	}

	// (c) Chain elements 2 and 3. This is the binding that the transaction's
	// published tx_viewing_pk equals TxViewingSk * G, which is what makes the
	// ciphertext below worth anything.
	txCompressed := p256.CompressPubkey(api, p256.ScalarMulGenerator(api, w.TxViewingSk))
	txLo, txHi := Pack33To2FECircuit(api, txCompressed)

	sealed := Envelope{
		Plaintext: w.TxViewingSk,
		EphSk:     w.EphSk,
		AuditorPk: w.AuditorPk,
		Info:      auditEncInfo,
	}.Seal(api)
	legacyOutputHashChain, legacyDisclosureHash := disclosureElements(
		api, rangeChecker, w.TxViewingSk, w.Salt, w.Outputs, w.OutputCountSelected,
	)
	outputHashChain, disclosureHash := anonymousDisclosureElements(api, w)
	outputHashChain = api.Select(w.Anonymous, outputHashChain, legacyOutputHashChain)
	disclosureHash = api.Select(w.Anonymous, disclosureHash, legacyDisclosureHash)
	saltField := gadget.PackBytesBE(api, w.Salt[:])[0]

	return [12]frontend.Variable{
		w.PrivateTxHash,
		txLo, txHi,
		sealed.AuditorLo, sealed.AuditorHi,
		sealed.EphLo, sealed.EphHi,
		sealed.CiphertextHash,
		outputHashChain,
		saltField,
		disclosureHash,
		w.Anonymous,
	}
}

type Envelope struct {
	Plaintext [32]frontend.Variable
	EphSk     [32]frontend.Variable
	AuditorPk [32]frontend.Variable
	Info      string
}

type Sealed struct {
	AuditorLo      frontend.Variable
	AuditorHi      frontend.Variable
	EphLo          frontend.Variable
	EphHi          frontend.Variable
	CiphertextHash frontend.Variable
}

// Seal owns the envelope's byte, canonical-key, and nonzero-DH checks.
func (e Envelope) Seal(api frontend.API) Sealed {
	auditorCompressed, ephCompressed, dh := AgreeAuditKey(api, e.EphSk, e.AuditorPk)
	auditorLo, auditorHi := Pack33To2FECircuit(api, auditorCompressed)
	ephLo, ephHi := Pack33To2FECircuit(api, ephCompressed)

	// (g) Bind the raw ECDH output to both public keys (see pack.go).
	sharedSecret := DeriveAuditSharedSecret(api, dh, ephCompressed, auditorCompressed)

	// (h) Poseidon key schedule, mirroring the Rust host KDF
	// (zolana_keypair::symmetric_apply with the same info string).
	key, nonce := ve.KeySchedule(api, sharedSecret, infoVars(e.Info), len(e.Info))

	// (i) AES-256-CTR over the 32-byte plaintext scalar. Ciphertext integrity
	// comes from the hash in (j), not from a GCM tag.
	ciphertext := aes.NewCipher(api, key).CTREncrypt(nonce, e.Plaintext[:])

	// (j) Chain element 8.
	ciphertextHash := gadget.HashBytes(api, ciphertext)

	return Sealed{
		AuditorLo:      auditorLo,
		AuditorHi:      auditorHi,
		EphLo:          ephLo,
		EphHi:          ephHi,
		CiphertextHash: ciphertextHash,
	}
}

func infoVars(info string) []frontend.Variable {
	out := make([]frontend.Variable, len(info))
	for i, b := range info {
		out[i] = frontend.Variable(b)
	}
	return out
}
