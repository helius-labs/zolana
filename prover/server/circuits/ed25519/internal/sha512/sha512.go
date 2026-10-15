package sha512

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/ed25519/internal/lookup"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
)

// Spread slices end at rotation cuts, so rotations are linear in constrained
// slices. One parity lookup extracts five XOR lanes. The commitment binds every lookup.

type sha512Word struct {
	pieces, spreads []frontend.Variable
	widths          []int
	value, spread4  frontend.Variable
}

// Boundaries include every rotation and shift position, after noir-lang/sha512
// src/encoding.nr at e92ffb47. One-bit slices need only a Boolean constraint.
var sha512ScheduleWidths = []int{1, 5, 1, 1, 8, 3, 8, 8, 8, 8, 1, 8, 1, 3}
var sha512AWidths = []int{8, 8, 8, 4, 6, 5, 8, 1, 8, 8}
var sha512EWidths = []int{8, 6, 4, 6, 8, 8, 1, 6, 1, 8, 8}
var sha512ByteWidths = []int{8, 8, 8, 8, 8, 8, 8, 8}

type sha512Engine struct {
	api     frontend.API
	parity  *lookup.Table
	spreads [9]*lookup.Table
	rc      *emfield.RangeChecker
}

type sha512Key struct{}

// rangePieceBits matches the Ed25519 field layout, so both share one range table.
const rangePieceBits = 11

// Share immutable spread/parity tables, never hash state. Each Hash call
// starts from its own IV and message schedule.
func sha512New(api frontend.API) *sha512Engine {
	kv := api.Compiler().(r1cKeyValueStore)
	if e, ok := kv.GetKeyValue(sha512Key{}).(*sha512Engine); ok {
		return e
	}
	e := &sha512Engine{api: api, parity: lookup.New(api, 1), rc: emfield.NewRangeCheckerFor(api, rangePieceBits)}
	for i := 0; i < 1024; i++ {
		var parity uint64
		for j := 0; j < 5; j++ {
			parity |= uint64((i>>(2*j))&1) << j
		}
		e.parity.Insert([]frontend.Variable{parity})
	}
	kv.SetKeyValue(sha512Key{}, e)
	return e
}

func sha512Pow(n int) *big.Int { return new(big.Int).Lsh(big.NewInt(1), uint(n)) }
func sha512Spread(v uint64, stride, bits int) *big.Int {
	out := new(big.Int)
	for i := 0; i < bits; i++ {
		if v>>i&1 != 0 {
			out.SetBit(out, stride*i, 1)
		}
	}
	return out
}

// Constrain exact slice width and base-four spreading on both constant and
// witness paths. Lookup membership binds input and output together.
func (e *sha512Engine) spreadPiece(v frontend.Variable, width int) frontend.Variable {
	if width < 1 || width > 8 {
		panic("sha512: invalid spread width")
	}
	if c, ok := e.api.Compiler().ConstantValue(v); ok {
		if c.Sign() < 0 || c.BitLen() > width {
			panic("sha512: constant slice out of range")
		}
		return sha512Spread(c.Uint64(), 2, width)
	}
	if width == 1 {
		e.api.AssertIsBoolean(v)
		return v
	}
	if e.spreads[width] == nil {
		t := lookup.New(e.api, 1)
		for i := 0; i < 1<<width; i++ {
			t.Insert([]frontend.Variable{sha512Spread(uint64(i), 2, width)})
		}
		e.spreads[width] = t
	}
	return e.spreads[width].Lookup(v)[0]
}

// Every slice has its exact bit width from a separate lookup table. Both
// recompositions fit in 64 and 128 bits respectively, below the native field.
func (e *sha512Engine) pieces(values []frontend.Variable, widths []int) sha512Word {
	if len(values) != len(widths) {
		panic("sha512: slice shape")
	}
	w := sha512Word{pieces: values, widths: widths, spreads: make([]frontend.Variable, len(values)), value: 0, spread4: 0}
	off := 0
	for i, v := range values {
		w.spreads[i] = e.spreadPiece(v, widths[i])
		w.value = e.api.Add(w.value, e.api.Mul(v, sha512Pow(off)))
		w.spread4 = e.api.Add(w.spread4, e.api.Mul(w.spreads[i], sha512Pow(2*off)))
		off += widths[i]
	}
	if off != 64 {
		panic("sha512: slices must fill a word")
	}
	return w
}

// Construct a trusted 64-bit word with the requested complete slice layout.
func (e *sha512Engine) constant(v uint64, widths []int) sha512Word {
	values := make([]frontend.Variable, len(widths))
	for i, width := range widths {
		values[i] = v & ((1 << width) - 1)
		v >>= width
	}
	return e.pieces(values, widths)
}

// Return bounded candidate low-word slices. The caller must bind w.value
// to sum or a bounded carry. This helper deliberately does not assert equality.
func (e *sha512Engine) split(sum frontend.Variable, widths []int) sha512Word {
	if c, ok := e.api.Compiler().ConstantValue(sum); ok {
		return e.constant(c.Uint64(), widths)
	}
	in := []frontend.Variable{sum}
	for _, width := range widths {
		in = append(in, width)
	}
	values, err := e.api.Compiler().NewHint(sha512SlicesHint, len(widths), in...)
	if err != nil {
		panic(err)
	}
	return e.pieces(values, widths)
}

// Range-check every byte and bind its little-endian reconstruction to slices.
func (e *sha512Engine) word(bytes [8]frontend.Variable) sha512Word {
	value := frontend.Variable(0)
	for i, b := range bytes {
		e.spreadPiece(b, 8)
		value = e.api.Add(value, e.api.Mul(b, sha512Pow(8*i)))
	}
	w := e.split(value, sha512ScheduleWidths)
	e.api.AssertIsEqual(w.value, value)
	return w
}

// Take an exact slice-boundary prefix from an already-constrained word.
func (e *sha512Engine) lowSpread(w sha512Word, n int) frontend.Variable {
	low, off := frontend.Variable(0), 0
	for i, width := range w.widths {
		if off == n {
			return low
		}
		if off+width > n {
			panic("sha512: rotation is not a slice boundary")
		}
		low = e.api.Add(low, e.api.Mul(w.spreads[i], sha512Pow(2*off)))
		off += width
	}
	if off != n {
		panic("sha512: rotation out of bounds")
	}
	return low
}

// Rotate/shift a constrained spread word by a compile-time slice boundary.
// Removing its exact low prefix makes division by 4^n an integer operation.
func (e *sha512Engine) rotate(w sha512Word, n int, shift bool) frontend.Variable {
	low := e.lowSpread(w, n)
	inv := new(big.Int).ModInverse(sha512Pow(2*n), e.api.Compiler().Field())
	out := e.api.Mul(e.api.Sub(w.spread4, low), inv)
	if !shift {
		out = e.api.Add(out, e.api.Mul(low, sha512Pow(128-2*n)))
	}
	return out
}

// split indices are range-bound by their own lookup. Their recomposition
// fits below 2^130, hence no native-field wrap can change any lane.
func (e *sha512Engine) extractParity(sum frontend.Variable) frontend.Variable {
	const width, n, outputBits = 10, 13, 5
	if c, ok := e.api.Compiler().ConstantValue(sum); ok {
		// Constant folding follows the same table definition as the witness.
		if c.Sign() < 0 || c.BitLen() > width*n {
			panic("sha512: parity input exceeds 130 bits")
		}
		out := new(big.Int)
		for i := 0; i < n; i++ {
			x := new(big.Int).Rsh(c, uint(width*i)).Uint64() & ((1 << width) - 1)
			var v uint64
			for j := 0; j < outputBits; j++ {
				v |= ((x >> (2 * j)) & 1) << j
			}
			out.Add(out, new(big.Int).Lsh(new(big.Int).SetUint64(v), uint(outputBits*i)))
		}
		return out
	}
	indices, err := e.api.Compiler().NewHint(sha512ChunksHint, n, width, sum)
	if err != nil {
		panic(err)
	}
	recomposed, out := frontend.Variable(0), frontend.Variable(0)
	for i, idx := range indices {
		v := e.parity.Lookup(idx)[0]
		recomposed = e.api.Add(recomposed, e.api.Mul(idx, sha512Pow(width*i)))
		out = e.api.Add(out, e.api.Mul(v, sha512Pow(outputBits*i)))
	}
	e.api.AssertIsEqual(sum, recomposed)
	return out
}

// Compute the specified XOR of rotations. All lanes inherit word slice bounds.
func (e *sha512Engine) sigma(w sha512Word, a, b, c int, shift bool) frontend.Variable {
	return e.extractParity(e.api.Add(e.rotate(w, a, false), e.rotate(w, b, false), e.rotate(w, c, shift)))
}

// Derive majority from bounded words using the exact dense-integer identity.
func (e *sha512Engine) maj(a, b, c sha512Word) frontend.Variable {
	parity := e.extractParity(e.api.Add(a.spread4, b.spread4, c.spread4))
	// Per bit, a+b+c = XOR(a,b,c) + 2*Maj(a,b,c). Summing with
	// powers of two gives this exact dense-integer identity below 2^66.
	return e.api.Mul(e.api.Sub(e.api.Add(a.value, b.value, c.value), parity), new(big.Int).ModInverse(big.NewInt(2), e.api.Compiler().Field()))
}

// Derive choose from bounded words and two constrained parity extractions.
func (e *sha512Engine) ch(a, b, c sha512Word) frontend.Variable {
	ac := e.extractParity(e.api.Add(a.spread4, c.spread4))
	ab := e.extractParity(e.api.Add(a.spread4, b.spread4))
	// 2*Ch(a,b,c) = b+c+XOR(a,c)-XOR(a,b), bit by bit and as an
	// integer. The numerator is nonnegative, even and below 2^65.
	return e.api.Mul(e.api.Sub(e.api.Add(b.value, c.value, ac), ab), new(big.Int).ModInverse(big.NewInt(2), e.api.Compiler().Field()))
}

// Reduce a sum modulo 2^64 with a bounded carry. Each operand must already
// be a bounded 64-bit word/expression. At most eight operands prevent native wrap.
func (e *sha512Engine) add(widths []int, terms ...frontend.Variable) sha512Word {
	if len(terms) == 0 || len(terms) > 8 {
		panic("sha512: adder needs one to eight bounded operands")
	}
	sum := sum(e.api, terms...)
	if c, ok := e.api.Compiler().ConstantValue(sum); ok {
		return e.constant(c.Uint64(), widths)
	}
	out := e.split(sum, widths)
	inv := new(big.Int).ModInverse(sha512Pow(64), e.api.Compiler().Field())
	e.rc.Check(e.api.Mul(e.api.Sub(sum, out.value), inv), 4)
	return out
}

var sha512IV = [8]uint64{0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179}
var sha512K = [80]uint64{
	0x428a2f98d728ae22,
	0x7137449123ef65cd,
	0xb5c0fbcfec4d3b2f,
	0xe9b5dba58189dbbc,
	0x3956c25bf348b538,
	0x59f111f1b605d019,
	0x923f82a4af194f9b,
	0xab1c5ed5da6d8118,
	0xd807aa98a3030242,
	0x12835b0145706fbe,
	0x243185be4ee4b28c,
	0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f,
	0x80deb1fe3b1696b1,
	0x9bdc06a725c71235,
	0xc19bf174cf692694,
	0xe49b69c19ef14ad2,
	0xefbe4786384f25e3,
	0x0fc19dc68b8cd5b5,
	0x240ca1cc77ac9c65,
	0x2de92c6f592b0275,
	0x4a7484aa6ea6e483,
	0x5cb0a9dcbd41fbd4,
	0x76f988da831153b5,
	0x983e5152ee66dfab,
	0xa831c66d2db43210,
	0xb00327c898fb213f,
	0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2,
	0xd5a79147930aa725,
	0x06ca6351e003826f,
	0x142929670a0e6e70,
	0x27b70a8546d22ffc,
	0x2e1b21385c26c926,
	0x4d2c6dfc5ac42aed,
	0x53380d139d95b3df,
	0x650a73548baf63de,
	0x766a0abb3c77b2a8,
	0x81c2c92e47edaee6,
	0x92722c851482353b,
	0xa2bfe8a14cf10364,
	0xa81a664bbc423001,
	0xc24b8b70d0f89791,
	0xc76c51a30654be30,
	0xd192e819d6ef5218,
	0xd69906245565a910,
	0xf40e35855771202a,
	0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8,
	0x1e376c085141ab53,
	0x2748774cdf8eeb99,
	0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63,
	0x4ed8aa4ae3418acb,
	0x5b9cca4f7763e373,
	0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc,
	0x78a5636f43172f60,
	0x84c87814a1f0ab72,
	0x8cc702081a6439ec,
	0x90befffa23631e28,
	0xa4506cebde82bde9,
	0xbef9a3f7b2c67915,
	0xc67178f2e372532b,
	0xca273eceea26619c,
	0xd186b8c721c0c207,
	0xeada7dd6cde0eb1e,
	0xf57d4f7fee6ed178,
	0x06f067aa72176fba,
	0x0a637dc5a2c898a6,
	0x113f9804bef90dae,
	0x1b710b35131c471b,
	0x28db77f523047d84,
	0x32caab7b40c72493,
	0x3c9ebe0a15c9bebc,
	0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6,
	0x597f299cfc657e2a,
	0x5fcb6fab3ad6faec,
	0x6c44198c4a475817,
}

// Hash range-checks every byte of a fixed-length message and returns the big-endian
// digest. It needs BN254 and the commitment-aware Groth16 verifier.
func Hash(api frontend.API, message []frontend.Variable) [64]frontend.Variable {
	// 1 - Lookup packing and modular carries require the reviewed native-field width.
	if api.Compiler().Field().Cmp(ecc.BN254.ScalarField()) != 0 {
		panic("sha512: BN254 native field required")
	}
	e := sha512New(api)
	// 2 - Fixed-length padding has no hinted quotient or prover-selected suffix.
	n := len(message)
	blocks := (n+16)/128 + 1
	padded := make([]frontend.Variable, blocks*128)
	copy(padded, message)
	for j := n; j < len(padded); j++ {
		var b byte
		if j == n {
			b = 0x80
		} else if j >= len(padded)-8 {
			b = byte(uint64(n) * 8 >> uint(8*(len(padded)-1-j)))
		}
		padded[j] = b
	}
	// 3 - Share tables, never chaining state between independent messages.
	var state [8]sha512Word
	for i, v := range sha512IV {
		widths := sha512AWidths
		if i >= 4 {
			widths = sha512EWidths
		}
		state[i] = e.constant(v, widths)
	}
	// 4 - Every word addition constrains its 64-bit result and carry before reuse.
	for block := 0; block < blocks; block++ {
		var w [80]sha512Word
		for i := 0; i < 16; i++ {
			var b [8]frontend.Variable
			for j := range b {
				b[j] = padded[128*block+8*i+7-j]
			}
			w[i] = e.word(b)
		}
		for i := 16; i < 80; i++ {
			w[i] = e.add(sha512ScheduleWidths, w[i-16].value, e.sigma(w[i-15], 1, 8, 7, true), w[i-7].value, e.sigma(w[i-2], 19, 61, 6, true))
		}
		s := state
		for i, k := range sha512K {
			ne := e.add(sha512EWidths, s[3].value, s[7].value, e.sigma(s[4], 14, 18, 41, false), e.ch(s[4], s[5], s[6]), k, w[i].value)
			na := e.add(sha512AWidths, ne.value, e.sigma(s[0], 28, 34, 39, false), e.maj(s[0], s[1], s[2]), api.Sub(new(big.Int).Sub(sha512Pow(64), big.NewInt(1)), s[3].value), 1)
			s = [8]sha512Word{na, s[0], s[1], s[2], ne, s[4], s[5], s[6]}
		}
		for i := range state {
			widths := sha512AWidths
			if i >= 4 {
				widths = sha512EWidths
			}
			if block == blocks-1 {
				widths = sha512ByteWidths
			}
			state[i] = e.add(widths, state[i].value, s[i].value)
		}
	}
	// 5 - Bounded byte pieces fix one digest encoding at the signature boundary.
	var out [64]frontend.Variable
	for i, w := range state {
		for j := 0; j < 8; j++ {
			out[8*i+j] = w.pieces[7-j]
		}
	}
	return out
}

func init() { solver.RegisterHint(sha512ChunksHint, sha512SlicesHint) }

// Suggest parity chunks. extractParity checks width, membership and recomposition.
func sha512ChunksHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || !inputs[0].IsInt64() || inputs[0].Int64() < 1 || inputs[0].Int64() > 16 {
		return fmt.Errorf("sha512 chunks: invalid width")
	}
	width := uint(inputs[0].Int64())
	v := new(big.Int).Set(inputs[1])
	mask := new(big.Int).Sub(sha512Pow(int(width)), big.NewInt(1))
	for _, o := range outputs {
		o.And(v, mask)
		v.Rsh(v, width)
	}
	return nil
}

// Suggest word slices. The split method bounds them and its caller binds the whole word.
func sha512SlicesHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != len(outputs)+1 {
		return fmt.Errorf("sha512 slices: invalid shape")
	}
	v := new(big.Int).Set(inputs[0])
	total := 0
	for i, out := range outputs {
		if !inputs[i+1].IsInt64() {
			return fmt.Errorf("sha512 slices: invalid width")
		}
		width := int(inputs[i+1].Int64())
		if width < 1 || width > 8 {
			return fmt.Errorf("sha512 slices: invalid width")
		}
		out.And(v, new(big.Int).Sub(sha512Pow(width), big.NewInt(1)))
		v.Rsh(v, uint(width))
		total += width
	}
	if total != 64 {
		return fmt.Errorf("sha512 slices: invalid total width")
	}
	return nil
}

func sum(api frontend.API, terms ...frontend.Variable) frontend.Variable {
	switch len(terms) {
	case 0:
		return 0
	case 1:
		return terms[0]
	default:
		return api.Add(terms[0], terms[1], terms[2:]...)
	}
}

type r1cKeyValueStore interface {
	SetKeyValue(key, value any)
	GetKeyValue(key any) any
}
