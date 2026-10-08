package aes

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

const (
	// FIPS 197-upd1, Table 3: AES-256 uses a 32-byte key, 16-byte blocks,
	// and 14 rounds. Sec. 5.2 expands the key into 15 round keys (240 bytes).
	// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
	aes256KeyBytes   = 32
	aes256Rounds     = 14
	aes256RoundBytes = 16 * (aes256Rounds + 1)
	blockBytes       = 16

	// NIST SP 800-38D, Sec. 7.1, steps 2-3: for a 96-bit nonce,
	// J0 = nonce || 0x00000001, so inc32(J0) starts encryption at counter 2.
	// This gadget uses the CTR stream without GCM's authentication tag.
	// https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
	ctrFirstCounter = 2
	// Counters 2 through 2^32-1 allow 2^32-2 blocks without wrapping,
	// matching the plaintext limit of 2^39-256 bits in Sec. 5.2.1.
	maxCtrBlocks = 1<<32 - ctrFirstCounter
)

// Cipher shares AES-256 key-expansion constraints across CTR streams.
type Cipher struct {
	keys *roundKeys
}

// CTREncrypt encrypts bytes with AES-256-CTR, starting at nonce || 0x00000002.
// Use NewCipher to share a key expansion across several streams.
func CTREncrypt(api frontend.API, key [aes256KeyBytes]frontend.Variable, nonceBytes [12]frontend.Variable, plaintext []frontend.Variable) []frontend.Variable {
	return NewCipher(api, key).CTREncrypt(nonceBytes, plaintext)
}

// NewCipher constrains the key bytes and expands the key once for this circuit.
func NewCipher(api frontend.API, key [aes256KeyBytes]frontend.Variable) *Cipher {
	return &Cipher{keys: expandRoundKeys(api, key)}
}

// CTREncrypt starts a fresh stream at nonce || 0x00000002 using the expanded key.
// Distinct messages encrypted with this key require distinct nonces.
func (c *Cipher) CTREncrypt(nonceBytes [12]frontend.Variable, plaintext []frontend.Variable) []frontend.Variable {
	// 1. Reject plaintext lengths that would wrap the 32-bit counter.
	if blocks := (len(plaintext) + blockBytes - 1) / blockBytes; blocks > maxCtrBlocks {
		panic(fmt.Sprintf("ctr: %d blocks wrap the 32-bit counter, at most %d", blocks, maxCtrBlocks))
	}

	// 2. Constrain and spread the nonce bytes.
	keys := c.keys
	t := keys.tables
	spreadNonce := make([]frontend.Variable, len(nonceBytes))
	for i := range nonceBytes {
		spreadNonce[i] = t.spreadByte(nonceBytes[i])
	}

	// 3. Apply the initial round key to the nonce and initialize the stream.
	stream := &ctrStream{keys: keys, nonceState: keys.addRoundKey(spreadNonce, 0), cachedHigh: -1}

	// 4. Encrypt each plaintext block, including a partial tail.
	ciphertext := make([]frontend.Variable, 0, len(plaintext))
	for offset, block := 0, 0; offset < len(plaintext); offset, block = offset+blockBytes, block+1 {
		end := min(offset+blockBytes, len(plaintext))
		ciphertext = append(ciphertext, stream.encryptBlock(uint32(block+ctrFirstCounter), plaintext[offset:end])...)
	}
	return ciphertext
}

type ctrStream struct {
	keys       *roundKeys
	nonceState []frontend.Variable
	cachedHigh int64
	firstRound [blockBytes]frontend.Variable
	columnZero frontend.Variable
}

// encryptBlock returns ciphertext for up to one block of plaintext.
func (s *ctrStream) encryptBlock(counter uint32, plaintextBytes []frontend.Variable) []frontend.Variable {
	// 1. Constrain and spread the plaintext bytes.
	t := s.keys.tables
	spreadPlaintext := make([]frontend.Variable, len(plaintextBytes))
	for i, value := range plaintextBytes {
		spreadPlaintext[i] = t.spreadByte(value)
	}

	// 2. Refresh cached first-round columns when the upper counter bytes change.
	high := int64(counter >> bitsPerByte)
	if high != s.cachedHigh {
		s.cachedHigh = high
		var state [blockBytes]frontend.Variable
		copy(state[:12], s.nonceState)
		for position := 12; position < 15; position++ {
			counterByteIndex := blockBytes - 1 - position
			counterByte := byte(counter >> uint(bitsPerByte*counterByteIndex))
			state[position] = s.counterByte(position, counterByte)
		}
		for column := 1; column < wordBytes; column++ {
			start := column * wordBytes
			end := start + wordBytes
			copy(s.firstRound[start:end], s.keys.roundColumn(1, column, &state))
		}
		s.columnZero = s.keys.columnSum(1, 0, &state, 0, 1, 2)
	}

	// 3. Complete the first round using the current low counter byte.
	last := s.counterByte(15, byte(counter))
	state := s.firstRound
	spreadCounterContribution := t.substitute(3, last)
	spreadColumnSum := t.api.Add(s.columnZero, spreadCounterContribution)
	columnBytes := t.decodeXorBytes(spreadColumnSum, wordBytes)
	copy(state[:wordBytes], columnBytes)

	// 4. Apply AES rounds 2 through 13.
	for round := 2; round < aes256Rounds; round++ {
		var next [blockBytes]frontend.Variable
		for column := 0; column < wordBytes; column++ {
			start := column * wordBytes
			end := start + wordBytes
			copy(next[start:end], s.keys.roundColumn(round, column, &state))
		}
		state = next
	}

	// 5. Apply the final AES round and XOR with the plaintext.
	sums := make([]frontend.Variable, len(spreadPlaintext))
	for i := range sums {
		spreadSubstitutedByte := t.substitute(sboxRegion, state[byteOrder[i]])
		spreadRoundKeyByte := s.keys.spreadBytes[aes256Rounds*blockBytes+i]
		sums[i] = t.api.Add(spreadSubstitutedByte, spreadRoundKeyByte, spreadPlaintext[i])
	}
	return t.xorBytes(sums)
}

func (s *ctrStream) counterByte(position int, value byte) frontend.Variable {
	if value == 0 {
		return s.keys.bytes[position]
	}
	sum := s.keys.tables.api.Add(s.keys.spreadBytes[position], s.keys.tables.spreadConstant(value))
	return s.keys.tables.xorBytes([]frontend.Variable{sum})[0]
}

type roundKeys struct {
	tables      *spreadTables
	spreadBytes []frontend.Variable
	bytes       []frontend.Variable
}

var roundConstants = [...]byte{0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}

// expandRoundKeys implements AES-256 KEYEXPANSION from FIPS 197-upd1,
// Sec. 5.2, Algorithm 2. Appendix A.3 gives a worked AES-256 example.
// Offsets here are in bytes; the specification indexes four-byte words.
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf#page=26
func expandRoundKeys(api frontend.API, key [aes256KeyBytes]frontend.Variable) *roundKeys {
	t := sharedSpreadTables(api)
	// Keep ordinary bytes for S-box indices and spread bytes for XOR arithmetic.
	spreadRoundKeyBytes := make([]frontend.Variable, aes256RoundBytes)
	roundKeyBytes := make([]frontend.Variable, aes256RoundBytes)
	for i := 0; i < aes256KeyBytes; i++ {
		roundKeyBytes[i] = key[i]
		spreadRoundKeyBytes[i] = t.spreadByte(key[i])
	}
	for i := aes256KeyBytes; i < aes256RoundBytes; i += wordBytes {
		var mixed [wordBytes]frontend.Variable
		switch i % aes256KeyBytes {
		case 0:
			for j := range mixed {
				mixed[j] = t.substitute(sboxRegion, roundKeyBytes[i-wordBytes+(j+1)%wordBytes])
			}
			mixed[0] = api.Add(mixed[0], t.spreadConstant(roundConstants[i/aes256KeyBytes]))
		case 16:
			for j := range mixed {
				mixed[j] = t.substitute(sboxRegion, roundKeyBytes[i-wordBytes+j])
			}
		default:
			copy(mixed[:], spreadRoundKeyBytes[i-wordBytes:i])
		}
		sums := make([]frontend.Variable, wordBytes)
		for j := range sums {
			sums[j] = api.Add(spreadRoundKeyBytes[i-aes256KeyBytes+j], mixed[j])
		}
		copy(roundKeyBytes[i:i+wordBytes], t.xorBytes(sums))
		for j := 0; j < wordBytes; j++ {
			spreadRoundKeyBytes[i+j] = t.spreadByte(roundKeyBytes[i+j])
		}
	}
	return &roundKeys{tables: t, spreadBytes: spreadRoundKeyBytes, bytes: roundKeyBytes}
}

func (k *roundKeys) addRoundKey(spreadBytes []frontend.Variable, offset int) []frontend.Variable {
	sums := make([]frontend.Variable, len(spreadBytes))
	for i := range sums {
		sums[i] = k.tables.api.Add(spreadBytes[i], k.spreadBytes[offset+i])
	}
	return k.tables.xorBytes(sums)
}

func (k *roundKeys) roundColumn(round, column int, state *[blockBytes]frontend.Variable) []frontend.Variable {
	return k.tables.decodeXorBytes(k.columnSum(round, column, state, 0, 1, 2, 3), wordBytes)
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

func (k *roundKeys) word(round, column int) frontend.Variable {
	start := round*blockBytes + column*wordBytes
	return k.tables.word(k.spreadBytes[start : start+wordBytes])
}

const (
	chunkLaneBase    = 6
	lanesPerChunk    = 4
	chunkRadix       = 1296
	bitsPerByte      = 8
	wordBytes        = 4
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
	for j := range t.byteWeights {
		t.byteWeights[j] = spreadValue(1<<uint(bitsPerByte*j), bitsPerByte*wordBytes, chunkLaneBase)
	}
	t.substitution = logderivlookup.New(api)
	for region := 0; region < sboxRegion; region++ {
		for a := 0; a < tableRegionSize; a++ {
			t.substitution.Insert(spreadValue(uint64(substitutionWords[region][a]), bitsPerByte*wordBytes, chunkLaneBase))
		}
	}
	for a := 0; a < tableRegionSize; a++ {
		t.substitution.Insert(spreadValue(uint64(sbox0[a]), bitsPerByte, chunkLaneBase))
	}
	t.bytes = logderivlookup.New(api)
	for a := 0; a < tableRegionSize; a++ {
		t.bytes.Insert(spreadValue(uint64(a), bitsPerByte, chunkLaneBase))
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
		out = append(out, t.decodeXorBytes(t.word(sums[start:end]), end-start)...)
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
		out[j] = t.api.Add(nibbles[2*j], t.api.Mul(nibbles[2*j+1], 16))
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
