package aes

import (
	"encoding/binary"
	"fmt"

	"github.com/consensys/gnark/frontend"
)

const (
	// FIPS 197-upd1, Table 3: AES-256 uses a 32-byte key, 16-byte blocks,
	// and 14 rounds. Sec. 5.2 expands the key into 15 round keys (240 bytes).
	// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
	aes256KeyBytes   = 32
	aes256Rounds     = 14
	aes256RoundBytes = 16 * (aes256Rounds + 1)
	blockBytes       = 16
	bitsPerByte      = 8
	wordBytes        = 4
	columnsPerBlock  = blockBytes / wordBytes

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

// NewCipher constrains the key bytes and expands the key once for this circuit.
func NewCipher(api frontend.API, key [aes256KeyBytes]frontend.Variable) *Cipher {
	return &Cipher{keys: expandRoundKeys(api, key)}
}

// CTREncrypt encrypts bytes with AES-256-CTR, starting at nonce || 0x00000002.
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
	for offset := 0; offset < len(plaintext); offset += blockBytes {
		end := min(offset+blockBytes, len(plaintext))
		counter := uint32(offset/blockBytes + ctrFirstCounter)
		ciphertext = append(ciphertext, stream.encryptBlock(counter, plaintext[offset:end])...)
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
	var counterBytes [4]byte
	binary.BigEndian.PutUint32(counterBytes[:], counter)

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
		for counterByteIndex, counterByte := range counterBytes[:3] {
			position := len(s.nonceState) + counterByteIndex
			state[position] = s.counterByte(position, counterByte)
		}
		for column := 1; column < columnsPerBlock; column++ {
			start := column * wordBytes
			end := start + wordBytes
			copy(s.firstRound[start:end], s.keys.roundColumn(1, column, &state))
		}
		s.columnZero = s.keys.columnSum(1, 0, &state, 0, 1, 2)
	}

	// 3. Complete the first round using the current low counter byte.
	last := s.counterByte(blockBytes-1, counterBytes[3])
	state := s.firstRound
	spreadCounterContribution := t.substitute(3, last)
	spreadColumnSum := t.api.Add(s.columnZero, spreadCounterContribution)
	columnBytes := t.decodeXorBytes(spreadColumnSum, wordBytes)
	copy(state[:wordBytes], columnBytes)

	// 4. Apply AES rounds 2 through 13.
	for round := 2; round < aes256Rounds; round++ {
		var next [blockBytes]frontend.Variable
		for column := 0; column < columnsPerBlock; column++ {
			start := column * wordBytes
			end := start + wordBytes
			copy(next[start:end], s.keys.roundColumn(round, column, &state))
		}
		state = next
	}

	// 5. Apply the final AES round and XOR with the plaintext.
	spreadFinalRoundKey := s.keys.spreadBytes[aes256Rounds*blockBytes:]
	sums := make([]frontend.Variable, len(spreadPlaintext))
	for i := range sums {
		spreadSubstitutedByte := t.substitute(sboxRegion, state[byteOrder[i]])
		spreadRoundKeyByte := spreadFinalRoundKey[i]
		sums[i] = t.api.Add(spreadSubstitutedByte, spreadRoundKeyByte, spreadPlaintext[i])
	}
	return t.xorBytes(sums)
}

func (s *ctrStream) counterByte(position int, value byte) frontend.Variable {
	if value == 0 {
		return s.keys.bytes[position]
	}
	spreadKeyByte := s.keys.spreadBytes[position]
	spreadCounterByte := s.keys.tables.spreadConstant(value)
	sum := s.keys.tables.api.Add(spreadKeyByte, spreadCounterByte)
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
		previousWordBytes := roundKeyBytes[i-wordBytes : i]
		spreadPreviousWordBytes := spreadRoundKeyBytes[i-wordBytes : i]
		earlierWordStart := i - aes256KeyBytes
		spreadEarlierWordBytes := spreadRoundKeyBytes[earlierWordStart : earlierWordStart+wordBytes]
		currentWordBytes := roundKeyBytes[i : i+wordBytes]
		spreadCurrentWordBytes := spreadRoundKeyBytes[i : i+wordBytes]

		var mixed [wordBytes]frontend.Variable
		switch i % aes256KeyBytes {
		case 0:
			for j := range mixed {
				rotatedByteIndex := (j + 1) % wordBytes
				previousByte := previousWordBytes[rotatedByteIndex]
				mixed[j] = t.substitute(sboxRegion, previousByte)
			}
			roundConstant := roundConstants[i/aes256KeyBytes]
			spreadRoundConstant := t.spreadConstant(roundConstant)
			mixed[0] = api.Add(mixed[0], spreadRoundConstant)
		case 16:
			for j := range mixed {
				previousByte := previousWordBytes[j]
				mixed[j] = t.substitute(sboxRegion, previousByte)
			}
		default:
			copy(mixed[:], spreadPreviousWordBytes)
		}
		sums := make([]frontend.Variable, wordBytes)
		for j := range sums {
			sums[j] = api.Add(spreadEarlierWordBytes[j], mixed[j])
		}
		copy(currentWordBytes, t.xorBytes(sums))
		for j, roundKeyByte := range currentWordBytes {
			spreadCurrentWordBytes[j] = t.spreadByte(roundKeyByte)
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
	spreadColumnSum := k.columnSum(round, column, state, 0, 1, 2, 3)
	return k.tables.decodeXorBytes(spreadColumnSum, wordBytes)
}

var columnSources = [columnsPerBlock][wordBytes]int{
	{0, 5, 10, 15},
	{4, 9, 14, 3},
	{8, 13, 2, 7},
	{12, 1, 6, 11},
}

func (k *roundKeys) columnSum(round, column int, state *[blockBytes]frontend.Variable, regions ...int) frontend.Variable {
	start := round*blockBytes + column*wordBytes
	end := start + wordBytes
	spreadRoundKeyWord := k.spreadBytes[start:end]
	sum := k.tables.word(spreadRoundKeyWord)
	for _, region := range regions {
		stateByteIndex := columnSources[column][region]
		spreadContribution := k.tables.substitute(region, state[stateByteIndex])
		sum = k.tables.api.Add(sum, spreadContribution)
	}
	return sum
}
