package aes

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// SubstitutionLookup, SpreadByteLookup and ChunkParityLookup stand for the
// logderivlookup tables of spread_bytes.go during Lean extraction. Each lookup
// is an opaque predicate relating Index to one table entry; the table contents
// reach Lean separately and lookup soundness is an explicit assumption.
type SubstitutionLookup struct {
	Index frontend.Variable
}

func (SubstitutionLookup) DefineGadget(frontend.API) interface{} { panic("extraction-only") }

func (SubstitutionLookup) OpaqueOutputs() int { return 1 }

type SpreadByteLookup struct {
	Index frontend.Variable
}

func (SpreadByteLookup) DefineGadget(frontend.API) interface{} { panic("extraction-only") }

func (SpreadByteLookup) OpaqueOutputs() int { return 1 }

type ChunkParityLookup struct {
	Index frontend.Variable
}

func (ChunkParityLookup) DefineGadget(frontend.API) interface{} { panic("extraction-only") }

func (ChunkParityLookup) OpaqueOutputs() int { return 1 }

type opaqueTable struct {
	api    frontend.API
	gadget func(index frontend.Variable) abstractor.GadgetDefinition
}

var _ logderivlookup.Table = opaqueTable{}

func (opaqueTable) Insert(frontend.Variable) int { panic("extraction tables hold no entries") }

func (t opaqueTable) Lookup(indices ...frontend.Variable) []frontend.Variable {
	values := make([]frontend.Variable, len(indices))
	for i, index := range indices {
		values[i] = abstractor.Call(t.api, t.gadget(index))
	}
	return values
}

// The AES step gadgets below keep their *Constrained bodies on a builder and
// become named Lean definitions under the extractor.

// AesDecodeWord is decodeWordSum: the XOR bytes encoded by a spread word sum.
type AesDecodeWord struct {
	Sum       frontend.Variable
	ByteCount int
}

func (g AesDecodeWord) DefineGadget(api frontend.API) interface{} {
	return sharedSpreadTables(api).decodeWordSumConstrained(g.Sum, g.ByteCount)
}

func (t *spreadTables) decodeWordSum(spreadSum frontend.Variable, byteCount int) []frontend.Variable {
	if !abstractor.Extracting(t.api) {
		return t.decodeWordSumConstrained(spreadSum, byteCount)
	}
	return abstractor.Call1(t.api, AesDecodeWord{Sum: spreadSum, ByteCount: byteCount})
}

// AesRoundColumn is one MixColumns column of a middle round: the four source
// state bytes (ShiftRows order) and the spread round-key word give four bytes.
type AesRoundColumn struct {
	State          []frontend.Variable
	RoundKeySpread []frontend.Variable
}

func (g AesRoundColumn) DefineGadget(api frontend.API) interface{} {
	t := sharedSpreadTables(api)
	return t.decodeWordSum(t.columnSumOf(g.RoundKeySpread, g.State, 0, 1, 2, 3), wordBytes)
}

func (k *roundKeys) roundColumn(round, column int, state *[blockBytes]frontend.Variable) []frontend.Variable {
	if !abstractor.Extracting(k.tables.api) {
		return k.roundColumnConstrained(round, column, state)
	}
	spreadRoundKeyWord, sources := k.columnInputs(round, column, state)
	return abstractor.Call1(k.tables.api, AesRoundColumn{State: sources, RoundKeySpread: spreadRoundKeyWord})
}

// AesFinalRound is the last AES round of one block XORed with the plaintext:
// SubBytes and ShiftRows of State, the spread final round key and the spread
// plaintext bytes give the ciphertext bytes.
type AesFinalRound struct {
	State           []frontend.Variable
	RoundKeySpread  []frontend.Variable
	PlaintextSpread []frontend.Variable
}

func (g AesFinalRound) DefineGadget(api frontend.API) interface{} {
	return sharedSpreadTables(api).finalRoundConstrained(g.State, g.RoundKeySpread, g.PlaintextSpread)
}

func (t *spreadTables) finalRound(state, spreadFinalRoundKey, spreadPlaintext []frontend.Variable) []frontend.Variable {
	if !abstractor.Extracting(t.api) {
		return t.finalRoundConstrained(state, spreadFinalRoundKey, spreadPlaintext)
	}
	return abstractor.Call1(t.api, AesFinalRound{State: state, RoundKeySpread: spreadFinalRoundKey[:len(spreadPlaintext)], PlaintextSpread: spreadPlaintext})
}

// AesCounterByte is a key byte XORed with a nonzero constant counter byte.
type AesCounterByte struct {
	SpreadKeyByte frontend.Variable
	Counter       int
}

func (g AesCounterByte) DefineGadget(api frontend.API) interface{} {
	return sharedSpreadTables(api).counterByteConstrained(g.SpreadKeyByte, byte(g.Counter))
}

func (t *spreadTables) counterByte(spreadKeyByte frontend.Variable, value byte) frontend.Variable {
	if !abstractor.Extracting(t.api) {
		return t.counterByteConstrained(spreadKeyByte, value)
	}
	return abstractor.Call(t.api, AesCounterByte{SpreadKeyByte: spreadKeyByte, Counter: int(value)})
}

// AesKeyExpansion is the AES-256 key schedule; it returns the 240 spread
// round-key bytes and the 240 round-key bytes.
type AesKeyExpansion struct {
	Key []frontend.Variable
}

func (g AesKeyExpansion) DefineGadget(api frontend.API) interface{} {
	var key [aes256KeyBytes]frontend.Variable
	copy(key[:], g.Key)
	keys := expandRoundKeysConstrained(api, key)
	return [][]frontend.Variable{keys.spreadBytes, keys.bytes}
}

func expandRoundKeys(api frontend.API, key [aes256KeyBytes]frontend.Variable) *roundKeys {
	if !abstractor.Extracting(api) {
		return expandRoundKeysConstrained(api, key)
	}
	expanded := abstractor.Call2(api, AesKeyExpansion{Key: key[:]})
	return &roundKeys{tables: sharedSpreadTables(api), spreadBytes: expanded[0], bytes: expanded[1]}
}

func newExtractionTables(t *spreadTables) *spreadTables {
	t.substitution = opaqueTable{t.api, func(index frontend.Variable) abstractor.GadgetDefinition {
		return SubstitutionLookup{Index: index}
	}}
	t.bytes = opaqueTable{t.api, func(index frontend.Variable) abstractor.GadgetDefinition {
		return SpreadByteLookup{Index: index}
	}}
	t.chunks = opaqueTable{t.api, func(index frontend.Variable) abstractor.GadgetDefinition {
		return ChunkParityLookup{Index: index}
	}}
	return t
}
