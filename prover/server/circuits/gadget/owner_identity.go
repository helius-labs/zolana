package gadget

import (
	"github.com/consensys/gnark/frontend"
)

// Owner identities are algorithm-tagged hash_bytes_33 values:
//
//	solana_identity(pk) := hash_bytes_33(0x53 || pk)   // 'S', ed25519 or PDA
//
// The tag lands in the top byte of chunk 0, so the derivation still costs one
// permutation, exactly like the untagged hash_bytes_32, and an identity never
// equals the untagged hash of the same bytes. The tag avoids the SEC1 prefixes
// 0x02, 0x03 and 0x04 so an owner identity can never equal the hash_bytes_33
// viewing-key commitment over a compressed P256 key.
//
// Most Solana identities arrive as finished values hashed by SPP from the
// transaction signers. The Ed25519 owner rail computes the identity in the
// circuit from the key whose signature it verifies, so an in-circuit Ed25519
// owner and a runtime signer of the same key share one identity.
const SolanaOwnerTag = 0x53

// SolanaOwnerIdentity commits a Solana owner by its 32-byte public key (the
// compressed Edwards y encoding for an Ed25519 key). It must match the host
// derivation byte for byte.
func SolanaOwnerIdentity(api frontend.API, pk [32]frontend.Variable) frontend.Variable {
	return HashBytes(api, append([]frontend.Variable{SolanaOwnerTag}, pk[:]...))
}
