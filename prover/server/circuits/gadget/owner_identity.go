package gadget

import (
	"github.com/consensys/gnark/frontend"
)

// Owner identities are algorithm-tagged so a P256 x-coordinate and a Solana
// key that share bytes never share an identity:
//
//	solana_identity(pk) := hash_bytes_33(0x53 || pk)   // 'S', ed25519 or PDA
//	p256_identity(x)    := hash_bytes_33(0x50 || x)    // 'P', x-coordinate
//
// The tag lands in the top byte of chunk 0, so the two derivations feed
// different first Poseidon inputs for every key pair and still cost one
// permutation, exactly like the untagged hash_bytes_32. The tags avoid the SEC1
// prefixes 0x02, 0x03 and 0x04 so an owner identity can never equal the
// hash_bytes_33 viewing-key commitment over a compressed P256 key. Only the
// P256 tag is defined here: circuits compute the P256 identity themselves,
// while every Solana identity arrives as a finished value hashed by SPP.
const P256OwnerTag = 0x50

// P256OwnerIdentity commits a P256 owner by its 32-byte big-endian
// x-coordinate. This is the protocol owner identity for a P256 owner and must
// match the host derivations byte for byte.
func P256OwnerIdentity(api frontend.API, x [32]frontend.Variable) frontend.Variable {
	return HashBytes(api, append([]frontend.Variable{P256OwnerTag}, x[:]...))
}
