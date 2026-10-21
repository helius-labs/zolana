package gadget

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

const HashBytesChunkSize = 31

// Range-checks each byte, and with no length tag each input length needs its own domain.
func HashBytes(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	return HashBytesWith(api, rangecheck.New(api), bytes)
}

// HashBytesWith is HashBytes through the given byte checker.
func HashBytesWith(api frontend.API, rc frontend.Rangechecker, bytes []frontend.Variable) frontend.Variable {
	return HashChain(api, PackBytesBEWith(api, rc, bytes))
}

// HashBoundedBytes is HashBytes for bytes the caller constrains to 8 bits.
func HashBoundedBytes(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	return HashBytesWith(api, BoundedBytes{}, bytes)
}

// BoundedBytes skips the byte check, for bytes the caller constrains to 8 bits where they are produced.
type BoundedBytes struct{}

func (BoundedBytes) Check(frontend.Variable, int) {}

// Range-checks each byte, the last chunk stays unpadded.
func PackBytesBE(api frontend.API, bytes []frontend.Variable) []frontend.Variable {
	return PackBytesBEWith(api, rangecheck.New(api), bytes)
}

// PackBytesBEWith is PackBytesBE through the given byte checker.
func PackBytesBEWith(api frontend.API, rc frontend.Rangechecker, bytes []frontend.Variable) []frontend.Variable {
	fields := make([]frontend.Variable, 0, (len(bytes)+HashBytesChunkSize-1)/HashBytesChunkSize)
	for offset := 0; offset < len(bytes); offset += HashBytesChunkSize {
		fields = append(fields, BytesToFieldWith(api, rc, bytes[offset:min(offset+HashBytesChunkSize, len(bytes))]))
	}
	return fields
}

// SolanaOwnerIdentity binds the exact 32-byte authorization encoding under the
// existing Solana owner domain. Curve and signature validity remain obligations
// of the signature gadget. This boundary proves byte widths and tagged hashing.
func SolanaOwnerIdentity(api frontend.API, key [32]frontend.Variable) frontend.Variable {
	return HashBytes(api, solanaOwnerPreimage(key))
}

// SolanaOwnerIdentityBounded is SolanaOwnerIdentity for key bytes the caller constrains to 8 bits.
func SolanaOwnerIdentityBounded(api frontend.API, key [32]frontend.Variable) frontend.Variable {
	return HashBoundedBytes(api, solanaOwnerPreimage(key))
}

func solanaOwnerPreimage(key [32]frontend.Variable) []frontend.Variable {
	return append([]frontend.Variable{0x53}, key[:]...)
}
