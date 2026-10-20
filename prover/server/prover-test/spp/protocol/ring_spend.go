package protocol

// RingSpendMessagePrefix separates a ring spend from every other Ed25519 message the owner key signs.
var RingSpendMessagePrefix = []byte("zolana ring spend v1")

// RingSpendMessage is the bytes the hidden owner signs, the ring address keeps a signature from spending in another ring.
func RingSpendMessage(ringProgram [32]byte, digest [32]byte) []byte {
	message := make([]byte, 0, len(RingSpendMessagePrefix)+64)
	message = append(message, RingSpendMessagePrefix...)
	message = append(message, ringProgram[:]...)
	return append(message, digest[:]...)
}
