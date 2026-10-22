package ringaudit

import (
	"crypto/ecdh"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// PackedSlotSecret mirrors base.PackedSlot.Secret.
func PackedSlotSecret(t testing.TB, txViewingSk [32]byte, salt [16]byte, i int, firstNullifier *big.Int) *big.Int {
	t.Helper()
	keyLo, keyHi := pack32(txViewingSk)
	return spptest.MustPoseidonHash(t, big.NewInt(base.PackedSlotSecretDomain), keyLo, keyHi, new(big.Int).SetBytes(salt[:]), big.NewInt(int64(i)), firstNullifier)
}

// DeliveredSlotSecret mirrors base.DeliveredSlot.Secret over X25519(tx_viewing_sk, u).
func DeliveredSlotSecret(t testing.TB, txViewingSk [32]byte, u [32]byte, salt [16]byte, i int, firstNullifier *big.Int) *big.Int {
	t.Helper()
	peer, err := ecdh.X25519().NewPublicKey(u[:])
	if err != nil {
		t.Fatal(err)
	}
	tx := XPrivateKey(t, txViewingSk)
	agreement, err := tx.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	dhLo, dhHi := pack32([32]byte(agreement))
	txLo, txHi := pack33(Tagged(tx.PublicKey().Bytes()))
	rLo, rHi := pack33(Tagged(u[:]))
	return spptest.MustPoseidonHash(t, big.NewInt(base.DeliveredSlotSecretDomain), dhLo, dhHi, txLo, txHi, rLo, rHi,
		new(big.Int).SetBytes(salt[:]), big.NewInt(int64(i)), firstNullifier)
}

// ConfidentialRingSecret mirrors base.ConfidentialRingSecret.
func ConfidentialRingSecret(t testing.TB, slotSecret *big.Int) *big.Int {
	t.Helper()
	return spptest.MustPoseidonHash(t, big.NewInt(base.ConfidentialRingSecretDomain), slotSecret)
}

// AnonymousRingSecret mirrors base.AnonymousRingSecret.
func AnonymousRingSecret(t testing.TB, slotSecret, tag *big.Int) *big.Int {
	t.Helper()
	return spptest.MustPoseidonHash(t, big.NewInt(base.AnonymousRingSecretDomain), slotSecret, tag)
}

// RingBlinding mirrors shared.DeriveRingOutputBlinding.
func RingBlinding(t testing.TB, firstNullifier, ringSecret *big.Int, i int) *big.Int {
	t.Helper()
	return spptest.MustPoseidonHash(t, big.NewInt(shared.RingOutputBlindingDomainV1), firstNullifier, ringSecret, big.NewInt(int64(i)))
}

// ExitBlinding is SPP's TXOB blinding of slot i under the output blinding seed.
func ExitBlinding(t testing.TB, firstNullifier, seedOut *big.Int, i int) *big.Int {
	t.Helper()
	blinding, err := protocol.OutputBlinding(firstNullifier, seedOut, i)
	return spptest.MustHash(t, blinding, err)
}

// DepositBlinding mirrors base.DepositBlinding.
func DepositBlinding(t testing.TB, blindingSecret *big.Int) *big.Int {
	t.Helper()
	return spptest.MustPoseidonHash(t, big.NewInt(base.DepositBlindingDomain), blindingSecret)
}

// InboxKey mirrors base.InboxKey over pack_be(0x04 ‖ u).
func InboxKey(t testing.TB, ringID *big.Int, u [32]byte) *big.Int {
	t.Helper()
	rLo, rHi := pack33(Tagged(u[:]))
	return spptest.MustPoseidonHash(t, big.NewInt(base.InboxKeyDomain), ringID, rLo, rHi)
}

// InboxTagDigest mirrors base.InboxTagDigest.
func InboxTagDigest(t testing.TB, inboxKey *big.Int, epoch, index uint64) *big.Int {
	t.Helper()
	return spptest.MustPoseidonHash(t, big.NewInt(base.InboxTagDomain), inboxKey, new(big.Int).SetUint64(epoch), new(big.Int).SetUint64(index))
}

// InboxTag is the low TagLen bytes of the inbox tag digest.
func InboxTag(t testing.TB, inboxKey *big.Int, epoch, index uint64) *big.Int {
	t.Helper()
	return LowTag(InboxTagDigest(t, inboxKey, epoch, index))
}

// PairKey mirrors base.PairKey.
func PairKey(t testing.TB, firstContact *big.Int) *big.Int {
	t.Helper()
	return spptest.MustPoseidonHash(t, big.NewInt(base.PairKeyDomain), firstContact)
}

// PairTag is the low TagLen bytes of base.PairTagDigest.
func PairTag(t testing.TB, pairKey *big.Int, epoch, index uint64) *big.Int {
	t.Helper()
	return LowTag(spptest.MustPoseidonHash(t, big.NewInt(base.PairTagDomain), pairKey, new(big.Int).SetUint64(epoch), new(big.Int).SetUint64(index)))
}

// LowTag mirrors base.TagField, the low TagLen bytes of a canonical field value.
func LowTag(value *big.Int) *big.Int {
	return new(big.Int).And(value, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 8*base.TagLen), big.NewInt(1)))
}

// SenderCommitment mirrors base.SenderCommitment.
func SenderCommitment(t testing.TB, senderPkHash, privateTxBlinding *big.Int) *big.Int {
	t.Helper()
	return spptest.MustPoseidonHash(t, big.NewInt(base.SenderCommitmentDomain), senderPkHash, privateTxBlinding)
}

// SealBody is the delivered body, AES-256-CTR of asset_address ‖ u64be(amount) under the stream of the slot secret.
func SealBody(t testing.TB, slotSecret *big.Int, assetAddress [32]byte, amount uint64) [base.BodyLen]byte {
	t.Helper()
	plaintext := binary.BigEndian.AppendUint64(append([]byte{}, assetAddress[:]...), amount)
	key, nonce := AuditStreamKeys(t, slotSecret)
	return [base.BodyLen]byte(ctrEncrypt(t, key, nonce, plaintext))
}

// AssetField is hash_bytes(asset_address).
func AssetField(t testing.TB, assetAddress [32]byte) *big.Int {
	t.Helper()
	asset, err := protocol.AssetField(assetAddress)
	return spptest.MustHash(t, asset, err)
}
