package protocol

import "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom/ringspend"

var RingSpendMessagePrefix = []byte(ringspend.MessagePrefix)

// RingSpendMessage is the bytes the hidden owner signs, the ring address keeps a signature from spending in another ring.
func RingSpendMessage(ringProgram [32]byte, digest [32]byte) []byte {
	message := make([]byte, 0, len(RingSpendMessagePrefix)+64)
	message = append(message, RingSpendMessagePrefix...)
	message = append(message, ringProgram[:]...)
	return append(message, digest[:]...)
}
