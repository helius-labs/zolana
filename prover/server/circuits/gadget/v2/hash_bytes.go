// Package checked localizes byte and field encoding obligations for new circuits.
package checked

import (
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// HashBytes constrains every input byte before the protocol's 31-byte BE packing
// and Poseidon chain. Length is fixed by the caller's protocol. Different lengths
// require separate commitment namespaces because this encoding has no length tag.
func HashBytes(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	fields := make([]frontend.Variable, 0, (len(bytes)+gadget.HashBytesChunkSize-1)/gadget.HashBytesChunkSize)
	for offset := 0; offset < len(bytes); offset += gadget.HashBytesChunkSize {
		end := min(offset+gadget.HashBytesChunkSize, len(bytes))
		fields = append(fields, BytesToField(api, bytes[offset:end]))
	}
	return gadget.HashChain(api, fields)
}

// SolanaOwnerIdentity binds the exact 32-byte authorization encoding under the
// existing Solana owner domain. Curve and signature validity remain obligations
// of the signature gadget. This boundary proves byte widths and tagged hashing.
func SolanaOwnerIdentity(api frontend.API, key [32]frontend.Variable) frontend.Variable {
	return HashBytes(api, append([]frontend.Variable{0x53}, key[:]...))
}
