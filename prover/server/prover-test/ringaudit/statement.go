package ringaudit

import (
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// AuditHead is what the program holds for the head of an audit statement, mirrors AuditHead in custom-rings/interface/src/statement.rs.
type AuditHead struct {
	FirstNullifier *big.Int
	RingProgramID  *big.Int
	TxViewingU     [32]byte
	AuditorPubkey  [33]byte
	EphU           [32]byte
	Sealed         []byte
	Salt           [16]byte
	// Layout is the raw statement value, Layout.Value of the transfer's flags.
	Layout int64
}

// Elements is CRAU, n0, ring_id, pack_be(0x04 ‖ tx_u), pack_be(auditor_pubkey), pack_be(0x04 ‖ eph_u), hash_bytes(sealed), salt, layout.
func (h AuditHead) Elements(t testing.TB) []*big.Int {
	t.Helper()
	txLo, txHi := pack33(Tagged(h.TxViewingU[:]))
	auditorLo, auditorHi := pack33(h.AuditorPubkey)
	ephLo, ephHi := pack33(Tagged(h.EphU[:]))
	return []*big.Int{
		big.NewInt(base.AuditStatementDomain), h.FirstNullifier, h.RingProgramID, txLo, txHi,
		auditorLo, auditorHi, ephLo, ephHi, HashBytes(t, h.Sealed), new(big.Int).SetBytes(h.Salt[:]), big.NewInt(h.Layout),
	}
}

// Layout is a transfer's layout flags, mirrors the Layout flags of package base.
type Layout struct {
	Exits        bool
	Escrow       bool
	DataFree     bool
	FullOpenings bool
}

func (l Layout) Value() int64 {
	return spptest.Bit(l.Exits)*base.LayoutExits | spptest.Bit(l.Escrow)*base.LayoutEscrow |
		spptest.Bit(l.DataFree)*base.LayoutDataFree | spptest.Bit(l.FullOpenings)*base.LayoutFullOpenings
}

func hasExit(utxos []Utxo) bool {
	return slices.ContainsFunc(utxos, Utxo.isExit)
}

// StatementOutput is one published output as an audit statement reads it.
type StatementOutput struct {
	Hash *big.Int
	// Exit chains zero for its body, recipient key and tag.
	Exit bool
	U    [32]byte
	// Tag is the TagLen-byte tag read as a field.
	Tag  *big.Int
	Body []byte
}

// AnonymousTail is what only an anonymous audit statement binds.
type AnonymousTail struct {
	PrivateTxHash    *big.Int
	Epoch            uint64
	FirstContactRoot *big.Int
	SenderCommitment *big.Int
}

// PackedStatement mirrors AuditKind::Packed, head ‖ output_chain, disclosure_chain.
func PackedStatement(t testing.TB, head AuditHead, outputs []StatementOutput, disclosure []*big.Int) []*big.Int {
	t.Helper()
	return append(head.Elements(t), outputChain(t, outputs), spptest.MustHashChain4(t, disclosure))
}

// DeliveredStatement mirrors AuditKind::Delivered, head ‖ output_chain, body_chain, disclosure_chain, recipient_key_chain.
func DeliveredStatement(t testing.TB, head AuditHead, outputs []StatementOutput, disclosure []*big.Int) []*big.Int {
	t.Helper()
	var keys []*big.Int
	for _, output := range outputs {
		lo, hi := pack32(output.U)
		if output.Exit {
			lo, hi = big.NewInt(0), big.NewInt(0)
		}
		keys = append(keys, lo, hi)
	}
	return append(head.Elements(t),
		outputChain(t, outputs), bodyChain(t, outputs), spptest.MustHashChain4(t, disclosure), spptest.MustHashChain4(t, keys))
}

// AnonymousStatement mirrors AuditKind::Anonymous, head ‖ output_chain, body_chain, disclosure_chain,
// private_tx_hash, tag_chain, epoch, first_contact_root, sender_commitment.
func AnonymousStatement(t testing.TB, head AuditHead, outputs []StatementOutput, disclosure []*big.Int, tail AnonymousTail) []*big.Int {
	t.Helper()
	tags := make([]*big.Int, len(outputs))
	for i, output := range outputs {
		tags[i] = big.NewInt(0)
		if !output.Exit {
			tags[i] = output.Tag
		}
	}
	return append(head.Elements(t),
		outputChain(t, outputs), bodyChain(t, outputs), spptest.MustHashChain4(t, disclosure), tail.PrivateTxHash,
		spptest.MustHashChain4(t, tags), new(big.Int).SetUint64(tail.Epoch), tail.FirstContactRoot, tail.SenderCommitment)
}

func outputChain(t testing.TB, outputs []StatementOutput) *big.Int {
	t.Helper()
	hashes := make([]*big.Int, len(outputs))
	for i, output := range outputs {
		hashes[i] = output.Hash
	}
	return spptest.MustHashChain4(t, hashes)
}

// bodyChain chains hash_bytes(body), zero on an exit.
func bodyChain(t testing.TB, outputs []StatementOutput) *big.Int {
	t.Helper()
	hashes := make([]*big.Int, len(outputs))
	for i, output := range outputs {
		hashes[i] = big.NewInt(0)
		if !output.Exit {
			hashes[i] = HashBytes(t, output.Body)
		}
	}
	return spptest.MustHashChain4(t, hashes)
}
