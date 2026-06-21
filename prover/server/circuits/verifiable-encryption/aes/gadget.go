package aes

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

// AESGadget is a reusable AES circuit component that shares lookup tables
// across multiple encrypt calls. Create one gadget per circuit and call
// Encrypt as many times as needed -- the five logderivlookup tables
// (4 T-tables + 1 S-box) are allocated once.
type AESGadget struct {
	api            frontend.API
	sbox           logderivlookup.Table
	t0, t1, t2, t3 logderivlookup.Table
	RCon           [11]frontend.Variable
}

// NewAESGadget creates a new AES gadget with shared lookup tables.
// Call this once per circuit, then use Encrypt for each block.
func NewAESGadget(api frontend.API) *AESGadget {
	t0 := logderivlookup.New(api)
	t1 := logderivlookup.New(api)
	t2 := logderivlookup.New(api)
	t3 := logderivlookup.New(api)
	sbox := logderivlookup.New(api)
	for i := 0; i < 256; i++ {
		t0.Insert(T[0][i])
		t1.Insert(T[1][i])
		t2.Insert(T[2][i])
		t3.Insert(T[3][i])
		sbox.Insert(sbox0[i])
	}

	RCon := [11]frontend.Variable{0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}

	return &AESGadget{api: api, sbox: sbox, RCon: RCon, t0: t0, t1: t1, t2: t2, t3: t3}
}

// Encrypt performs AES-256 encryption of a single 16-byte block.
// key must be 32 bytes. Returns the 16-byte ciphertext.
func (g *AESGadget) Encrypt(key []frontend.Variable, pt [16]frontend.Variable) [16]frontend.Variable {
	keySize := len(key)
	rounds := 14
	if keySize == 16 {
		rounds = 10
	}

	xk := g.ExpandKey(key)

	var state [16]frontend.Variable
	for i := 0; i < 16; i++ {
		state[i] = g.VariableXor(xk[i], pt[i], 8)
	}

	// Inner rounds: fused SubBytes+ShiftRows+MixColumns via T-tables
	for i := 1; i < rounds; i++ {
		k := i * 16
		t0 := g.XorSubWords(state[0], state[5], state[10], state[15], xk[k+0:k+4])
		t1 := g.XorSubWords(state[4], state[9], state[14], state[3], xk[k+4:k+8])
		t2 := g.XorSubWords(state[8], state[13], state[2], state[7], xk[k+8:k+12])
		t3 := g.XorSubWords(state[12], state[1], state[6], state[11], xk[k+12:k+16])

		copy(state[:4], t0)
		copy(state[4:8], t1)
		copy(state[8:12], t2)
		copy(state[12:16], t3)
	}

	// Final round: ShiftRows+SubBytes (no MixColumns)
	copy(state[:], g.ShiftSub(state))

	// Final AddRoundKey
	k := rounds * 16
	for i := 0; i < 4; i++ {
		state[i+0] = g.VariableXor(state[i+0], xk[k+i+0], 8)
		state[i+4] = g.VariableXor(state[i+4], xk[k+i+4], 8)
		state[i+8] = g.VariableXor(state[i+8], xk[k+i+8], 8)
		state[i+12] = g.VariableXor(state[i+12], xk[k+i+12], 8)
	}

	return state
}

// ExpandKey performs AES key expansion.
// For AES-256 (32-byte key), produces 240 bytes (60 words).
// For AES-128 (16-byte key), produces 176 bytes (44 words).
// Returns a flat slice of frontend.Variable (one per byte).
func (g *AESGadget) ExpandKey(key []frontend.Variable) []frontend.Variable {
	keySize := len(key)
	rounds := 14
	if keySize == 16 {
		rounds = 10
	}

	nWords := 4 * (rounds + 1)
	expand := make([]frontend.Variable, nWords*4)

	i := 0
	for i < keySize {
		expand[i] = key[i]
		expand[i+1] = key[i+1]
		expand[i+2] = key[i+2]
		expand[i+3] = key[i+3]
		i += 4
	}

	for i < nWords*4 {
		t0 := expand[i-4]
		t1 := expand[i-3]
		t2 := expand[i-2]
		t3 := expand[i-1]

		if i%keySize == 0 {
			// RotWord
			t0, t1, t2, t3 = t1, t2, t3, t0
			// SubWord
			tt := g.Subws(g.sbox, t0, t1, t2, t3)
			t0, t1, t2, t3 = tt[0], tt[1], tt[2], tt[3]
			// XOR with RCon
			t0 = g.VariableXor(t0, g.RCon[i/keySize], 8)
		}

		if rounds == 14 && i%keySize == 16 {
			// AES-256 extra SubWord
			tt := g.Subws(g.sbox, t0, t1, t2, t3)
			t0, t1, t2, t3 = tt[0], tt[1], tt[2], tt[3]
		}

		expand[i] = g.VariableXor(expand[i-keySize], t0, 8)
		expand[i+1] = g.VariableXor(expand[i-keySize+1], t1, 8)
		expand[i+2] = g.VariableXor(expand[i-keySize+2], t2, 8)
		expand[i+3] = g.VariableXor(expand[i-keySize+3], t3, 8)

		i += 4
	}

	return expand
}

// XorSubWords performs one column of an inner AES round:
// 4 T-table lookups (fused SubBytes+ShiftRows+MixColumns) XORed with 4 round key bytes.
// Returns 4 output bytes.
func (g *AESGadget) XorSubWords(a, b, c, d frontend.Variable, xk []frontend.Variable) []frontend.Variable {
	aa := g.t0.Lookup(a)[0]
	bb := g.t1.Lookup(b)[0]
	cc := g.t2.Lookup(c)[0]
	dd := g.t3.Lookup(d)[0]

	t0 := g.api.ToBinary(aa, 32)
	t1 := g.api.ToBinary(bb, 32)
	t2 := g.api.ToBinary(cc, 32)
	t3 := g.api.ToBinary(dd, 32)

	t4 := append(g.api.ToBinary(xk[0], 8), g.api.ToBinary(xk[1], 8)...)
	t4 = append(t4, g.api.ToBinary(xk[2], 8)...)
	t4 = append(t4, g.api.ToBinary(xk[3], 8)...)

	t := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		t[i] = g.api.Xor(t0[i], t1[i])
		t[i] = g.api.Xor(t[i], t2[i])
		t[i] = g.api.Xor(t[i], t3[i])
		t[i] = g.api.Xor(t[i], t4[i])
	}

	newWord := make([]frontend.Variable, 4)
	newWord[0] = g.api.FromBinary(t[:8]...)
	newWord[1] = g.api.FromBinary(t[8:16]...)
	newWord[2] = g.api.FromBinary(t[16:24]...)
	newWord[3] = g.api.FromBinary(t[24:32]...)
	return newWord
}

// ShiftSub performs the final-round transformation: ShiftRows permutation
// followed by SubBytes (no MixColumns).
func (g *AESGadget) ShiftSub(state [16]frontend.Variable) []frontend.Variable {
	t := make([]frontend.Variable, 16)
	for i := 0; i < 16; i++ {
		t[i] = state[byteOrder[i]]
	}
	return g.Subws(g.sbox, t...)
}

// SubBytes applies the S-box to all 16 bytes of the state.
func (g *AESGadget) SubBytes(state [16]frontend.Variable) [16]frontend.Variable {
	t := g.Subws(g.sbox, state[:]...)
	var res [16]frontend.Variable
	copy(res[:], t)
	return res
}

// VariableXor computes bitwise XOR of two frontend.Variables of the given bit size.
func (g *AESGadget) VariableXor(a frontend.Variable, b frontend.Variable, size int) frontend.Variable {
	bitsA := g.api.ToBinary(a, size)
	bitsB := g.api.ToBinary(b, size)
	x := make([]frontend.Variable, size)
	for i := 0; i < size; i++ {
		x[i] = g.api.Xor(bitsA[i], bitsB[i])
	}
	return g.api.FromBinary(x...)
}

// Subws performs S-box lookup on one or more byte values using the
// shared logderivlookup table.
func (g *AESGadget) Subws(sbox logderivlookup.Table, a ...frontend.Variable) []frontend.Variable {
	return sbox.Lookup(a...)
}
