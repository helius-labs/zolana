package aes

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

const (
	chunkLaneBase    = 6
	lanesPerChunk    = 4
	chunkRadix       = 1296
	tableRegionSize  = 256
	sboxRegion       = 4
	substitutionSize = 5 * tableRegionSize
)

type spreadTables struct {
	api          frontend.API
	byteWeights  [wordBytes]*big.Int
	substitution logderivlookup.Table
	bytes        logderivlookup.Table
	chunks       logderivlookup.Table
}

type compilerStore interface {
	SetKeyValue(key, value any)
	GetKeyValue(key any) any
}

type spreadTablesKey struct{}

func sharedSpreadTables(api frontend.API) *spreadTables {
	store, shared := api.Compiler().(compilerStore)
	if shared {
		if existing, ok := store.GetKeyValue(spreadTablesKey{}).(*spreadTables); ok {
			return existing
		}
	}
	t := newSpreadTables(api)
	if shared {
		store.SetKeyValue(spreadTablesKey{}, t)
	}
	return t
}

func newSpreadTables(api frontend.API) *spreadTables {
	t := &spreadTables{api: api}
	// Packed bytes have weights 1, 6^8, 6^16, and 6^24.
	spreadBase := big.NewInt(chunkLaneBase)
	for j := range t.byteWeights {
		exponent := big.NewInt(int64(bitsPerByte * j))
		t.byteWeights[j] = new(big.Int).Exp(spreadBase, exponent, nil)
	}
	t.substitution = logderivlookup.New(api)
	for region := 0; region < sboxRegion; region++ {
		for a := 0; a < tableRegionSize; a++ {
			substitutionWord := substitutionWords[region][a]
			spreadWord := spreadValue(uint64(substitutionWord), bitsPerByte*wordBytes, chunkLaneBase)
			t.substitution.Insert(spreadWord)
		}
	}
	for a := 0; a < tableRegionSize; a++ {
		substitutedByte := sbox0[a]
		spreadSubstitutedByte := spreadValue(uint64(substitutedByte), bitsPerByte, chunkLaneBase)
		t.substitution.Insert(spreadSubstitutedByte)
	}
	t.bytes = logderivlookup.New(api)
	for a := 0; a < tableRegionSize; a++ {
		spreadByte := spreadValue(uint64(a), bitsPerByte, chunkLaneBase)
		t.bytes.Insert(spreadByte)
	}
	t.chunks = logderivlookup.New(api)
	for c := 0; c < chunkRadix; c++ {
		t.chunks.Insert(chunkParity(c))
	}
	return t
}

// substitute returns a spread-encoded lookup result: sboxRegion applies only
// the AES S-box; regions 0..3 combine the S-box with a MixColumns contribution.
func (t *spreadTables) substitute(region int, index frontend.Variable) frontend.Variable {
	return t.substitution.Lookup(t.api.Add(index, region*tableRegionSize))[0]
}

func (t *spreadTables) spreadByte(value frontend.Variable) frontend.Variable {
	return t.bytes.Lookup(value)[0]
}

func (t *spreadTables) spreadConstant(value byte) *big.Int {
	return spreadValue(uint64(value), bitsPerByte, chunkLaneBase)
}

func (t *spreadTables) xorBytes(sums []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, 0, len(sums))
	for start := 0; start < len(sums); start += wordBytes {
		end := min(start+wordBytes, len(sums))
		spreadWordSum := t.word(sums[start:end])
		decodedBytes := t.decodeXorBytes(spreadWordSum, end-start)
		out = append(out, decodedBytes...)
	}
	return out
}

func (t *spreadTables) word(bytes []frontend.Variable) frontend.Variable {
	var acc frontend.Variable = 0
	for j, b := range bytes {
		acc = t.api.Add(acc, t.api.Mul(b, t.byteWeights[j]))
	}
	return acc
}

func (t *spreadTables) decodeXorBytes(spreadSum frontend.Variable, byteCount int) []frontend.Variable {
	out := make([]frontend.Variable, byteCount)
	chunks, err := t.api.NewHint(laneChunksHint, 2*byteCount, spreadSum)
	if err != nil {
		panic(err)
	}
	var recomposed frontend.Variable = 0
	weight := big.NewInt(1)
	for _, c := range chunks {
		recomposed = t.api.Add(recomposed, t.api.Mul(c, weight))
		weight = new(big.Int).Mul(weight, big.NewInt(chunkRadix))
	}
	t.api.AssertIsEqual(spreadSum, recomposed)
	nibbles := t.chunks.Lookup(chunks...)
	for j := range out {
		lowNibble := nibbles[2*j]
		highNibble := nibbles[2*j+1]
		out[j] = t.api.Add(lowNibble, t.api.Mul(highNibble, 16))
	}
	return out
}

func init() {
	solver.RegisterHint(laneChunksHint)
}

func laneChunksHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("lane chunks: expected one input, got %d", len(inputs))
	}
	rest := new(big.Int).Set(inputs[0])
	radix := big.NewInt(chunkRadix)
	for _, out := range outputs {
		rest.DivMod(rest, radix, out)
	}
	if rest.Sign() != 0 {
		return fmt.Errorf("lane chunks: sum exceeds %d chunks", len(outputs))
	}
	return nil
}

func spreadValue(value uint64, lanes int, base int64) *big.Int {
	out := new(big.Int)
	weight := big.NewInt(1)
	step := big.NewInt(base)
	for lane := 0; lane < lanes; lane++ {
		if (value>>uint(lane))&1 == 1 {
			out.Add(out, weight)
		}
		weight.Mul(weight, step)
	}
	return out
}

func chunkParity(chunk int) int {
	parity := 0
	for lane := 0; lane < lanesPerChunk; lane++ {
		parity |= (chunk % chunkLaneBase % 2) << uint(lane)
		chunk /= chunkLaneBase
	}
	return parity
}
