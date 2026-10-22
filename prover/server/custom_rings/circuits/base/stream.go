package base

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Tag stream bounds, mirrored by custom-rings/interface/src/stream.rs and sdk-libs/ts/src/keypair/ring-stream.ts.
const (
	// EpochSlots is the tag epoch length, the program sets epoch = slot / EpochSlots.
	EpochSlots = 1 << 18
	// StreamIndexBits bounds inbox and pair indexes alike, one range check serves every slot.
	StreamIndexBits = 6
	JInbox          = 1 << StreamIndexBits
	JPair           = 1 << StreamIndexBits
	// PairEpochBits bounds the epochs a pair stream lives after its anchor.
	PairEpochBits = 5
	KPairEpochs   = 1 << PairEpochBits
	// TagLen is the low248 width, the owner tag is 0x00 ‖ tag.
	TagLen = 31
)

// BodyLen is asset_address(32) ‖ u64be(amount), mirrored by RING_DELIVERED_BODY_LEN in program-libs/event/src/proofless.rs.
const BodyLen = 40

// PackedSlot is a packed rail slot secret preimage, TxViewingSk = pack_be(tx_viewing_sk).
type PackedSlot struct {
	TxViewingSk    [2]frontend.Variable
	Salt           frontend.Variable
	OutputIndex    frontend.Variable
	FirstNullifier frontend.Variable
}

// Secret is Poseidon(CRAS, key0, key1, salt, i, n0), held only by the sender and the auditor of tx_viewing_sk.
func (s PackedSlot) Secret(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		PackedSlotSecretDomain, s.TxViewingSk[0], s.TxViewingSk[1], s.Salt, s.OutputIndex, s.FirstNullifier,
	})
}

// DeliveredSlot is a delivered slot secret preimage, Agreement = pack_be(X25519(tx_viewing_sk, u)) and each key pack_be(0x04 ‖ u).
type DeliveredSlot struct {
	Agreement      [2]frontend.Variable
	TxPk           [2]frontend.Variable
	Recipient      [2]frontend.Variable
	Salt           frontend.Variable
	OutputIndex    frontend.Variable
	FirstNullifier frontend.Variable
}

// Secret is Poseidon(CRDS, dh0, dh1, txpk0, txpk1, r0, r1, salt, i, n0), the recipient rebuilds it from X25519(u_sk, tx_u).
func (s DeliveredSlot) Secret(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		DeliveredSlotSecretDomain, s.Agreement[0], s.Agreement[1], s.TxPk[0], s.TxPk[1],
		s.Recipient[0], s.Recipient[1], s.Salt, s.OutputIndex, s.FirstNullifier,
	})
}

// InboxKey is Poseidon(CRIK, ringID, r0, r1), recipient = pack_be(0x04 ‖ u) of the address viewing key.
func InboxKey(api frontend.API, ringID frontend.Variable, recipient [2]frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{InboxKeyDomain, ringID, recipient[0], recipient[1]})
}

// InboxTagDigest is Poseidon(CRIT, inboxKey, epoch, index), the caller bounds index below JInbox.
func InboxTagDigest(api frontend.API, inboxKey, epoch, index frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{InboxTagDomain, inboxKey, epoch, index})
}

// PairKey is Poseidon(CRPK, firstContact), firstContact the delivered slot secret of the anchor.
func PairKey(api frontend.API, firstContact frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{PairKeyDomain, firstContact})
}

// PairTagDigest is Poseidon(CRPT, pairKey, epoch, index), the caller bounds index below JPair.
func PairTagDigest(api frontend.API, pairKey, epoch, index frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{PairTagDomain, pairKey, epoch, index})
}

// TagField is low248(value), one tag per field since FieldLowBytesBE refuses the bytes of value + q.
func TagField(api frontend.API, rc frontend.Rangechecker, value frontend.Variable) frontend.Variable {
	return gadget.BytesToFieldWith(api, gadget.BoundedBytes{}, gadget.FieldLowBytesBE(api, rc, value, TagLen))
}

// ConfidentialRingSecret is Poseidon(CRRC, slotSecret), a ring secret no anchor accepts.
func ConfidentialRingSecret(api frontend.API, slotSecret frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{ConfidentialRingSecretDomain, slotSecret})
}

// AnonymousRingSecret is Poseidon(CRRA, slotSecret, tag), binding the published tag into the output blinding.
func AnonymousRingSecret(api frontend.API, slotSecret, tag frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{AnonymousRingSecretDomain, slotSecret, tag})
}

// SenderCommitment binds the anonymous audit and the member policy to one sender, private_tx_hash fixes the blinding both read.
func SenderCommitment(api frontend.API, senderPkHash, privateTxBlinding frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{SenderCommitmentDomain, senderPkHash, privateTxBlinding})
}
