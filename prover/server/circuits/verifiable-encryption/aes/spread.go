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
	byteLanes        = 8
	wordBytes        = 4
	tableRegionSize  = 256
	sboxRegion       = 4
	substitutionSize = 5 * tableRegionSize
)

const (
	aes256KeyBytes   = 32
	aes256Rounds     = 14
	aes256RoundBytes = 16 * (aes256Rounds + 1)
	blockBytes       = 16
)

var roundConstants = [...]byte{0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}

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
		weight = new(big.Int).Mul(weight, step)
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

type spreadTables struct {
	api          frontend.API
	byteWeights  [wordBytes]*big.Int
	substitution logderivlookup.Table
	bytes        logderivlookup.Table
	chunks       logderivlookup.Table
}

func newSpreadTables(api frontend.API) *spreadTables {
	t := &spreadTables{api: api}
	for j := range t.byteWeights {
		t.byteWeights[j] = spreadValue(1<<uint(byteLanes*j), byteLanes*wordBytes, chunkLaneBase)
	}
	t.substitution = logderivlookup.New(api)
	for region := 0; region < sboxRegion; region++ {
		for a := 0; a < tableRegionSize; a++ {
			t.substitution.Insert(spreadValue(uint64(substitutionWords[region][a]), byteLanes*wordBytes, chunkLaneBase))
		}
	}
	for a := 0; a < tableRegionSize; a++ {
		t.substitution.Insert(spreadValue(uint64(sbox0[a]), byteLanes, chunkLaneBase))
	}
	t.bytes = logderivlookup.New(api)
	for a := 0; a < tableRegionSize; a++ {
		t.bytes.Insert(spreadValue(uint64(a), byteLanes, chunkLaneBase))
	}
	t.chunks = logderivlookup.New(api)
	for c := 0; c < chunkRadix; c++ {
		t.chunks.Insert(chunkParity(c))
	}
	return t
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

func (t *spreadTables) substitute(region int, index frontend.Variable) frontend.Variable {
	return t.substitution.Lookup(t.api.Add(index, region*tableRegionSize))[0]
}

func (t *spreadTables) spreadByte(value frontend.Variable) frontend.Variable {
	return t.bytes.Lookup(value)[0]
}

func (t *spreadTables) spreadConstant(value byte) *big.Int {
	return spreadValue(uint64(value), byteLanes, chunkLaneBase)
}

func (t *spreadTables) word(bytes []frontend.Variable) frontend.Variable {
	var acc frontend.Variable = 0
	for j, b := range bytes {
		acc = t.api.Add(acc, t.api.Mul(b, t.byteWeights[j]))
	}
	return acc
}

func (t *spreadTables) laneParityBytes(sum frontend.Variable, n int) []frontend.Variable {
	out := make([]frontend.Variable, n)
	chunks, err := t.api.NewHint(laneChunksHint, 2*n, sum)
	if err != nil {
		panic(err)
	}
	var recomposed frontend.Variable = 0
	weight := big.NewInt(1)
	for _, c := range chunks {
		recomposed = t.api.Add(recomposed, t.api.Mul(c, weight))
		weight = new(big.Int).Mul(weight, big.NewInt(chunkRadix))
	}
	t.api.AssertIsEqual(sum, recomposed)
	nibbles := t.chunks.Lookup(chunks...)
	for j := range out {
		out[j] = t.api.Add(nibbles[2*j], t.api.Mul(nibbles[2*j+1], 16))
	}
	return out
}

func (t *spreadTables) xorBytes(sums []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, 0, len(sums))
	for start := 0; start < len(sums); start += wordBytes {
		end := min(start+wordBytes, len(sums))
		out = append(out, t.laneParityBytes(t.word(sums[start:end]), end-start)...)
	}
	return out
}

type roundKeys struct {
	tables  *spreadTables
	spread  []frontend.Variable
	compact []frontend.Variable
}

func (k *roundKeys) word(round, column int) frontend.Variable {
	start := round*blockBytes + column*wordBytes
	return k.tables.word(k.spread[start : start+wordBytes])
}

func expandRoundKeys(api frontend.API, key [aes256KeyBytes]frontend.Variable) *roundKeys {
	t := sharedSpreadTables(api)
	spread := make([]frontend.Variable, aes256RoundBytes)
	compact := make([]frontend.Variable, aes256RoundBytes)
	for i := 0; i < aes256KeyBytes; i++ {
		compact[i] = key[i]
		spread[i] = t.spreadByte(key[i])
	}
	for i := aes256KeyBytes; i < aes256RoundBytes; i += wordBytes {
		var mixed [wordBytes]frontend.Variable
		switch i % aes256KeyBytes {
		case 0:
			for j := range mixed {
				mixed[j] = t.substitute(sboxRegion, compact[i-wordBytes+(j+1)%wordBytes])
			}
			mixed[0] = api.Add(mixed[0], t.spreadConstant(roundConstants[i/aes256KeyBytes]))
		case 16:
			for j := range mixed {
				mixed[j] = t.substitute(sboxRegion, compact[i-wordBytes+j])
			}
		default:
			copy(mixed[:], spread[i-wordBytes:i])
		}
		sums := make([]frontend.Variable, wordBytes)
		for j := range sums {
			sums[j] = api.Add(spread[i-aes256KeyBytes+j], mixed[j])
		}
		copy(compact[i:i+wordBytes], t.xorBytes(sums))
		for j := 0; j < wordBytes; j++ {
			spread[i+j] = t.spreadByte(compact[i+j])
		}
	}
	return &roundKeys{tables: t, spread: spread, compact: compact}
}

var columnSources = [wordBytes][wordBytes]int{
	{0, 5, 10, 15},
	{4, 9, 14, 3},
	{8, 13, 2, 7},
	{12, 1, 6, 11},
}

func (k *roundKeys) columnSum(round, column int, state *[blockBytes]frontend.Variable, regions ...int) frontend.Variable {
	sum := k.word(round, column)
	for _, region := range regions {
		sum = k.tables.api.Add(sum, k.tables.substitute(region, state[columnSources[column][region]]))
	}
	return sum
}

func (k *roundKeys) roundColumn(round, column int, state *[blockBytes]frontend.Variable) []frontend.Variable {
	return k.tables.laneParityBytes(k.columnSum(round, column, state, 0, 1, 2, 3), wordBytes)
}

func (k *roundKeys) middleRounds(state [blockBytes]frontend.Variable, first int) [blockBytes]frontend.Variable {
	for round := first; round < aes256Rounds; round++ {
		var next [blockBytes]frontend.Variable
		for column := 0; column < wordBytes; column++ {
			copy(next[column*wordBytes:(column+1)*wordBytes], k.roundColumn(round, column, &state))
		}
		state = next
	}
	return state
}

func (k *roundKeys) finalRound(state [blockBytes]frontend.Variable, masks []frontend.Variable) []frontend.Variable {
	t := k.tables
	sums := make([]frontend.Variable, len(masks))
	for i := range sums {
		sums[i] = t.api.Add(t.substitute(sboxRegion, state[byteOrder[i]]), k.spread[aes256Rounds*blockBytes+i], masks[i])
	}
	return t.xorBytes(sums)
}

func (k *roundKeys) addRoundKey(spreadBytes []frontend.Variable, offset int) []frontend.Variable {
	sums := make([]frontend.Variable, len(spreadBytes))
	for i := range sums {
		sums[i] = k.tables.api.Add(spreadBytes[i], k.spread[offset+i])
	}
	return k.tables.xorBytes(sums)
}

type ctrStream struct {
	keys       *roundKeys
	nonceState []frontend.Variable
	cachedHigh int64
	firstRound [blockBytes]frontend.Variable
	columnZero frontend.Variable
}

func (s *ctrStream) counterByte(position int, value byte) frontend.Variable {
	if value == 0 {
		return s.keys.compact[position]
	}
	sum := s.keys.tables.api.Add(s.keys.spread[position], s.keys.tables.spreadConstant(value))
	return s.keys.tables.xorBytes([]frontend.Variable{sum})[0]
}

func (s *ctrStream) refreshFirstRound(counter uint32) {
	high := int64(counter >> byteLanes)
	if high == s.cachedHigh {
		return
	}
	s.cachedHigh = high
	var state [blockBytes]frontend.Variable
	copy(state[:12], s.nonceState)
	for position := 12; position < 15; position++ {
		state[position] = s.counterByte(position, byte(counter>>uint(byteLanes*(15-position))))
	}
	for column := 1; column < wordBytes; column++ {
		copy(s.firstRound[column*wordBytes:(column+1)*wordBytes], s.keys.roundColumn(1, column, &state))
	}
	s.columnZero = s.keys.columnSum(1, 0, &state, 0, 1, 2)
}

func (s *ctrStream) keystreamState(counter uint32) [blockBytes]frontend.Variable {
	s.refreshFirstRound(counter)
	t := s.keys.tables
	last := s.counterByte(15, byte(counter))
	state := s.firstRound
	copy(state[:wordBytes], t.laneParityBytes(t.api.Add(s.columnZero, t.substitute(3, last)), wordBytes))
	return s.keys.middleRounds(state, 2)
}

func CTREncrypt(api frontend.API, key [aes256KeyBytes]frontend.Variable, nonce [12]frontend.Variable, plaintext []frontend.Variable) []frontend.Variable {
	keys := expandRoundKeys(api, key)
	t := keys.tables
	spreadNonce := make([]frontend.Variable, len(nonce))
	for i := range nonce {
		spreadNonce[i] = t.spreadByte(nonce[i])
	}
	stream := &ctrStream{keys: keys, nonceState: keys.addRoundKey(spreadNonce, 0), cachedHigh: -1}
	ciphertext := make([]frontend.Variable, 0, len(plaintext))
	for offset, block := 0, 0; offset < len(plaintext); offset, block = offset+blockBytes, block+1 {
		end := min(offset+blockBytes, len(plaintext))
		masks := make([]frontend.Variable, end-offset)
		for i := range masks {
			masks[i] = t.spreadByte(plaintext[offset+i])
		}
		ciphertext = append(ciphertext, keys.finalRound(stream.keystreamState(uint32(block+2)), masks)...)
	}
	return ciphertext
}
