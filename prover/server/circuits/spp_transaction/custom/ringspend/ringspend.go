// Package ringspend imports nothing, so the host mirror in prover-test/spp/protocol reads the circuit's prefix.
package ringspend

// MessagePrefix separates a ring spend from every other Ed25519 message the owner key signs, mirrored by
// RING_SPEND_MESSAGE_PREFIX in sdk-libs/transaction/src/instructions/transact/transaction.rs.
const MessagePrefix = "zolana ring spend v1"
