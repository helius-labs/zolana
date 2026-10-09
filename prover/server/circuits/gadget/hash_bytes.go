package gadget

import "github.com/consensys/gnark/frontend"

const HashBytesChunkSize = 31

// HashBytes commits a fixed-size byte value using the protocol's canonical
// 31-byte big-endian packing and left-to-right Poseidon hash chain.
func HashBytes(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	return HashChain(api, PackBytesBE(api, bytes))
}

// PackBytesBE packs consecutive 31-byte chunks as big-endian field elements.
// The final partial chunk is packed without padding between its bytes.
func PackBytesBE(api frontend.API, bytes []frontend.Variable) []frontend.Variable {
	fields := make([]frontend.Variable, 0, (len(bytes)+HashBytesChunkSize-1)/HashBytesChunkSize)
	for offset := 0; offset < len(bytes); offset += HashBytesChunkSize {
		end := offset + HashBytesChunkSize
		if end > len(bytes) {
			end = len(bytes)
		}
		fields = append(fields, BytesToField(api, bytes[offset:end]))
	}
	return fields
}
