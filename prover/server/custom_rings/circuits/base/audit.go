// Package base proves what a ring auditor reads from a ring transfer.
package base

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// auditEncInfo is the audit stream schedule tag, mirrored by AUDIT_STREAM_INFO in custom-rings/interface/src/anonymous_output.rs.
const auditEncInfo = "CRING/adt1"

type AnonymousAuditShape struct {
	InputClass   int
	Outputs      int
	FullOpenings bool
}

// layout is the flags the shape fixes.
func (s AnonymousAuditShape) layout() int {
	if s.FullOpenings {
		return LayoutFullOpenings
	}
	return 0
}

// Audit key shapes, mirrored by the audit capacities and the anonymous classes of custom-rings/interface/src/disclosure.rs.
var (
	// PackedAuditCapacities leave confidential and delegate bodies unproven.
	PackedAuditCapacities = [...]int{2, 4}
	// DeliveredAuditCapacities prove every confidential body.
	DeliveredAuditCapacities = [...]int{8, 16}
	// AnonymousAuditShapes publish input hashes, a transfer takes the smallest class holding its published inputs.
	AnonymousAuditShapes = [...]AnonymousAuditShape{
		{InputClass: 4, Outputs: 2}, {InputClass: 8, Outputs: 2}, {InputClass: 12, Outputs: 2},
		{InputClass: 16, Outputs: 2}, {InputClass: 24, Outputs: 2}, {InputClass: 28, Outputs: 2},
		{InputClass: 4, Outputs: 4}, {InputClass: 8, Outputs: 4}, {InputClass: 12, Outputs: 4},
		{InputClass: 16, Outputs: 4}, {InputClass: 24, Outputs: 4},
		{InputClass: 4, Outputs: 8}, {InputClass: 8, Outputs: 8}, {InputClass: 12, Outputs: 8}, {InputClass: 16, Outputs: 8},
	}
	// AnonymousEntryShapes open every spent UTXO, the keys of a transfer that spends a default-ring note.
	AnonymousEntryShapes = [...]AnonymousAuditShape{
		{InputClass: 8, Outputs: 2, FullOpenings: true},
		{InputClass: 8, Outputs: 4, FullOpenings: true},
		{InputClass: 8, Outputs: 8, FullOpenings: true},
	}
)

type AuditWires struct {
	FirstNullifier frontend.Variable
	// RingID is hash_bytes(ring program address), the id SPP binds every ring output to.
	RingID      frontend.Variable
	TxViewingSk [32]frontend.Variable
	EphSk       [32]frontend.Variable
	AuditorPk   [32]frontend.Variable
	Salt        [16]frontend.Variable
	// SeedOut is SPP's output blinding seed Poseidon(TXOS, n0, blinding_seed), the seed of every exit blinding.
	SeedOut frontend.Variable
	Layout  frontend.Variable
}

type auditEnvelope struct {
	txSk [32]frontend.Variable
	// txPk is pack_be(0x04 ‖ tx_u).
	txPk [2]frontend.Variable
	// key is pack_be(tx_sk), the key of the CRAS slot secrets and the CROD pad.
	key        [2]frontend.Variable
	salt       frontend.Variable
	sealed     Sealed
	sealedHash frontend.Variable
}

// sealEnvelope binds tx_sk to its tagged public key and seals it to the auditor.
func (w AuditWires) sealEnvelope(api frontend.API, rc frontend.Rangechecker) auditEnvelope {
	// 1. The salt is 16 bytes, one field below 2^128 the program rebuilds from the instruction.
	salt := gadget.BytesToFieldWith(api, rc, w.Salt[:])
	// 2. The auditor reads the recovered bytes as they are, an unclamped alias would key another stream.
	AssertClamped(api, w.TxViewingSk)
	// 3. tx_u is the key of tx_sk, the generator bounds every secret byte the packings read.
	txPk := packBounded(api, TaggedPubkey(api, w.TxViewingSk))
	// 4. The envelope seals tx_sk to the auditor under the audit stream schedule.
	sealed := Envelope{Plaintext: w.TxViewingSk[:], EphSk: w.EphSk, AuditorPk: w.AuditorPk}.SealAuditStream(api)
	return auditEnvelope{
		txSk:   w.TxViewingSk,
		txPk:   [2]frontend.Variable(txPk),
		key:    [2]frontend.Variable(packBounded(api, w.TxViewingSk[:])),
		salt:   salt,
		sealed: sealed,
		// The cipher's byte tables bound every ciphertext byte.
		sealedHash: gadget.HashBoundedBytes(api, sealed.Ciphertext),
	}
}

// statementHead opens every audit statement, mirrored by AuditHead in custom-rings/interface/src/statement.rs.
//
//	CRAU, n0, ring_id, txpk0, txpk1, aud0, aud1, eph0, eph1, sealed_hash, salt, layout
func (e auditEnvelope) statementHead(w AuditWires) []frontend.Variable {
	return []frontend.Variable{
		AuditStatementDomain, w.FirstNullifier, w.RingID, e.txPk[0], e.txPk[1],
		e.sealed.Auditor[0], e.sealed.Auditor[1], e.sealed.Eph[0], e.sealed.Eph[1], e.sealedHash, e.salt, w.Layout,
	}
}

// outputSlot sorts a live UTXO into a ring output or an exit, a dummy or an unpublished slot is neither.
type outputSlot struct {
	OpenedUtxo
	live frontend.Variable
	ring frontend.Variable
	exit frontend.Variable
}

func classify(api frontend.API, o UtxoWires, opened OpenedUtxo, live frontend.Variable) outputSlot {
	// SPP holds every UTXO's ring id to 0 or the ring's on the same output hashes, AssertRingMemberOrFree in shared/ring.go.
	ring := api.Mul(live, IsNonZero(api, o.RingProgramID))
	return outputSlot{OpenedUtxo: opened, live: live, ring: ring, exit: api.Sub(live, ring)}
}

// assertBlinding pins a live UTXO's blinding to the one SPP derives, TXRB over ringSecret or TXOB over SeedOut on an exit.
func (w AuditWires) assertBlinding(api frontend.API, o UtxoWires, slot outputSlot, ringSecret frontend.Variable, i int) {
	blinding := shared.DeriveRingRailOutputBlinding(api, slot.exit, w.FirstNullifier, w.SeedOut, ringSecret, i)
	// Only a ring output carries the audited ring secret, an exit keeps the TXOB form no anchor opens.
	assertEqualWhen(api, slot.live, o.Blinding, blinding)
}

// AssertClamped pins the RFC 7748 clamped encoding, the one byte string per X25519 key.
func AssertClamped(api frontend.API, secret [32]frontend.Variable) {
	low := api.ToBinary(secret[0], 8)
	high := api.ToBinary(secret[31], 8)
	// Bits 0 to 2 are clear, the scalar is a multiple of the cofactor.
	for _, bit := range low[:3] {
		api.AssertIsEqual(bit, 0)
	}
	// Bit 254 is set and bit 255 is clear, the top RFC 7748 fixes.
	api.AssertIsEqual(high[6], 1)
	api.AssertIsEqual(high[7], 0)
}

// TaggedPubkey is 0x04 ‖ u of the clamped secret, the generator gadget bounds every secret byte.
func TaggedPubkey(api frontend.API, secret [32]frontend.Variable) []frontend.Variable {
	return tagged(x25519.ScalarMulGenerator(api, secret))
}

// tagged is the 0x04 ‖ u encoding of an X25519 key.
func tagged(u [32]frontend.Variable) []frontend.Variable {
	return append([]frontend.Variable{4}, u[:]...)
}

func assertEqualWhen(api frontend.API, cond, a, b frontend.Variable) {
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: cond, A: a, B: b})
}

func assertZeroWhen(api frontend.API, cond, v frontend.Variable) {
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: cond, V: v})
}

func validateLength(name string, got, want int) error {
	if got != want {
		return fmt.Errorf("base: %s count mismatch: got %d want %d", name, got, want)
	}
	return nil
}
