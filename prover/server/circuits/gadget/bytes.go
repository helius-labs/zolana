package gadget

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

const byteBits = 8

// BitChecker range-checks by bit decomposition, adding no BSB22 commitment.
type BitChecker struct{ API frontend.API }

func (c BitChecker) Check(v frontend.Variable, bits int) { c.API.ToBinary(v, bits) }

// BytesToFieldWith packs through the given checker, each byte checked once.
func BytesToFieldWith(api frontend.API, rc frontend.Rangechecker, bytes []frontend.Variable) frontend.Variable {
	if len(bytes) > HashBytesChunkSize+1 {
		panic("bytes to field: more than 32 bytes")
	}
	if len(bytes) == HashBytesChunkSize+1 {
		api.AssertIsEqual(bytes[0], 0)
	}
	if api.Compiler().Field().BitLen() <= byteBits*min(len(bytes), HashBytesChunkSize) {
		panic("bytes to field: packed integer can wrap the native field")
	}
	acc := frontend.Variable(0)
	for _, b := range bytes {
		rc.Check(b, byteBits)
		acc = api.Add(api.Mul(acc, 256), b)
	}
	return acc
}

// BitsToBytesBE groups little-endian bits into big-endian bytes. The bit count
// must be a multiple of eight.
func BitsToBytesBE(api frontend.API, bits []frontend.Variable) []frontend.Variable {
	if len(bits)%byteBits != 0 {
		panic("bits to bytes: bit count is not a multiple of eight")
	}
	n := len(bits) / byteBits
	out := make([]frontend.Variable, n)
	for i := range out {
		start := (n - 1 - i) * byteBits
		out[i] = api.FromBinary(bits[start : start+byteBits]...)
	}
	return out
}

// FieldToBytesBE returns the unique 32-byte encoding of a native field value.
// Full-width ToBinary enforces canonicality before any caller takes a suffix.
// Reducing a 256-bit representative modulo the field would admit byte aliases.
func FieldToBytesBE(api frontend.API, value frontend.Variable) [32]frontend.Variable {
	if api.Compiler().Field().BitLen() > 256 {
		panic("field to bytes: field exceeds 32 bytes")
	}
	bits := api.ToBinary(value)
	for len(bits) < 256 {
		bits = append(bits, 0)
	}
	var out [32]frontend.Variable
	copy(out[:], BitsToBytesBE(api, bits))
	return out
}

// FieldLowBytesBE returns the low n big-endian bytes of value, never of value+q.
func FieldLowBytesBE(api frontend.API, rc frontend.Rangechecker, value frontend.Variable, n int) []frontend.Variable {
	if n < 1 || n > HashBytesChunkSize {
		panic("field low bytes: byte count outside 1..31")
	}
	lowBits := byteBits * n
	out, err := api.Compiler().NewHint(lowBytesHint, n+1, value)
	if err != nil {
		panic(err)
	}
	high, bytes := out[0], out[1:]
	low := BytesToFieldWith(api, rc, bytes)
	assertCanonicalSplit(api, rc, value, high, low, lowBits)
	return bytes
}

// SplitField returns high and low of value = high*2^lowBits + low, never the split of value+q.
func SplitField(api frontend.API, rc frontend.Rangechecker, value frontend.Variable, lowBits int) (high, low frontend.Variable) {
	if lowBits < 1 || lowBits >= api.Compiler().Field().BitLen() {
		panic("split field: low width outside the field")
	}
	out, err := api.Compiler().NewHint(splitFieldHint, 2, value, lowBits)
	if err != nil {
		panic(err)
	}
	high, low = out[0], out[1]
	rc.Check(low, lowBits)
	assertCanonicalSplit(api, rc, value, high, low, lowBits)
	return high, low
}

// assertCanonicalSplit pins value = high*2^lowBits + low below q, the caller bounds low to lowBits.
func assertCanonicalSplit(api frontend.API, rc frontend.Rangechecker, value, high, low frontend.Variable, lowBits int) {
	q := api.Compiler().Field()
	// Without the bound, a high near q wraps qHigh - high into range.
	rc.Check(high, q.BitLen()-lowBits)
	api.AssertIsEqual(value, api.Add(api.Mul(high, new(big.Int).Lsh(big.NewInt(1), uint(lowBits))), low))
	qHigh := new(big.Int).Rsh(q, uint(lowBits))
	qLow := new(big.Int).Sub(q, new(big.Int).Lsh(qHigh, uint(lowBits)))
	// high is at most the high part of q.
	rc.Check(api.Sub(qHigh, high), qHigh.BitLen())
	atBound := api.IsZero(api.Sub(high, qHigh))
	// At the high part of q, low stays below the low part of q.
	rc.Check(api.Mul(atBound, api.Sub(new(big.Int).Sub(qLow, big.NewInt(1)), low)), lowBits)
}

func init() { solver.RegisterHint(lowBytesHint, splitFieldHint) }

func splitFieldHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || len(outputs) != 2 || !inputs[1].IsUint64() {
		return errors.New("split field: expecting a value, a low width and two outputs")
	}
	lowBits := uint(inputs[1].Uint64())
	outputs[0].Rsh(inputs[0], lowBits)
	outputs[1].Sub(inputs[0], new(big.Int).Lsh(outputs[0], lowBits))
	return nil
}

func lowBytesHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 || len(outputs) < 2 {
		return errors.New("low bytes: expecting one input and at least two outputs")
	}
	rest := new(big.Int).Set(inputs[0])
	for i := len(outputs) - 1; i >= 1; i-- {
		outputs[i].And(rest, big.NewInt(0xff))
		rest.Rsh(rest, byteBits)
	}
	outputs[0].Set(rest)
	return nil
}
