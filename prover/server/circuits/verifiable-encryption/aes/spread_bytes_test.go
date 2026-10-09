// Tested spread-byte invariants:
//
//  1. All 256 bytes match an independent base-6 encoding and decode back to
//     themselves; altered encodings are rejected.
//  2. Decoding sums of one to five spread bytes matches ordinary XOR, including
//     maximum digit sums; altered XOR results are rejected.
//  3. Chunk parity matches known answers and maps the 1296 chunks evenly onto
//     all 16 nibbles, with 81 chunks per nibble.
//  4. Multiple cipher instances reuse the compiler's spread tables.
//  5. Each lookup table rejects forged results at valid indices.
//  6. Hinted chunks must recompose their input and belong to the chunk table;
//     forged chunks are rejected both in isolation and during CTR encryption.
//  7. Removing recomposition or chunk membership admits the corresponding
//     attack, demonstrating why both checks are necessary.
//  8. Substitution indices need byte bounds: an unbounded index can escape
//     into the next region, while the byte lookup rejects that escape.
package aes

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"testing/quick"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/prover/prover-test/hintattack"
)

// Invariant 1: Encodes and decodes all 256 bytes correctly.
func TestSpreadByteExhaustive(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &spreadBytePropertyCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	var assignment spreadBytePropertyCircuit
	var expected [256]int
	for value := range assignment.Bytes {
		// Read the binary digits from most to least significant in base 6.
		// This reference uses neither spreadValue nor the production constants.
		for bit := 7; bit >= 0; bit-- {
			expected[value] = 6*expected[value] + ((value >> bit) & 1)
		}
		assignment.Bytes[value] = value
		assignment.Expected[value] = expected[value]
	}
	if err := solveSpreadCircuit(t, cs, &assignment); err != nil {
		t.Fatal(err)
	}
	for _, position := range []int{0, 1, 128, 255} {
		tampered := assignment
		tampered.Expected[position] = expected[position] + 1
		hintattack.RequireConstraintRejection(t, solveSpreadCircuit(t, cs, &tampered))
	}
}

// Invariant 2: Decodes sums of one to five bytes as XOR.
func TestSpreadByteSumParityMatchesXOR(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &spreadXORPropertyCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	for _, bytes := range [][5]byte{
		{},
		{0xff, 0xff, 0xff, 0xff, 0xff}, // Reach every lane's maximum sum of 5.
		{0xaa, 0x55, 0xaa, 0x55, 0xff},
		{0x80, 0x80, 0x80, 0x80, 0x80},
		{0x01, 0x01, 0x01, 0x01, 0x01},
	} {
		if err := solveSpreadCircuit(t, cs, spreadXORAssignment(bytes)); err != nil {
			t.Fatalf("bytes %x: %v", bytes, err)
		}
	}

	// Each generated input checks all prefix lengths, from one to five bytes.
	property := func(bytes [5]byte) bool {
		if err := solveSpreadCircuit(t, cs, spreadXORAssignment(bytes)); err != nil {
			t.Logf("bytes %x: %v", bytes, err)
			return false
		}
		return true
	}
	if err := quick.Check(property, &quick.Config{
		MaxCount: 100,
		Rand:     rand.New(rand.NewSource(1)),
	}); err != nil {
		t.Fatal(err)
	}

	for position := range 5 {
		tampered := spreadXORAssignment([5]byte{0xff, 0xff, 0xff, 0xff, 0xff})
		tampered.XOR[position] = 1 // Honest prefixes are 0 or 255.
		hintattack.RequireConstraintRejection(t, solveSpreadCircuit(t, cs, tampered))
	}
}

// Invariant 3: Matches known chunk parity values.
func TestLaneChunkTableKnownAnswers(t *testing.T) {
	// digits are the base-6 lane sums, least significant lane first; parity
	// carries bit i = digits[i] mod 2.
	entries := []struct {
		chunk  int
		digits [digitsPerChunk]int
		parity int
	}{
		{0, [digitsPerChunk]int{0, 0, 0, 0}, 0b0000},
		{1, [digitsPerChunk]int{1, 0, 0, 0}, 0b0001},
		{2, [digitsPerChunk]int{2, 0, 0, 0}, 0b0000},
		{5, [digitsPerChunk]int{5, 0, 0, 0}, 0b0001},
		{6, [digitsPerChunk]int{0, 1, 0, 0}, 0b0010},
		{7, [digitsPerChunk]int{1, 1, 0, 0}, 0b0011},
		{12, [digitsPerChunk]int{0, 2, 0, 0}, 0b0000},
		{36, [digitsPerChunk]int{0, 0, 1, 0}, 0b0100},
		{216, [digitsPerChunk]int{0, 0, 0, 1}, 0b1000},
		{259, [digitsPerChunk]int{1, 1, 1, 1}, 0b1111},
		{753, [digitsPerChunk]int{3, 5, 2, 3}, 0b1011},
		{1036, [digitsPerChunk]int{4, 4, 4, 4}, 0b0000},
		{1294, [digitsPerChunk]int{4, 5, 5, 5}, 0b1110},
		{1295, [digitsPerChunk]int{5, 5, 5, 5}, 0b1111},
	}
	for _, e := range entries {
		if got := e.digits[0] + 6*e.digits[1] + 36*e.digits[2] + 216*e.digits[3]; got != e.chunk {
			t.Fatalf("digits %v encode %d, entry says %d", e.digits, got, e.chunk)
		}
		if got := chunkParity(e.chunk); got != e.parity {
			t.Fatalf("chunk %d (digits %v): parity %04b, want %04b", e.chunk, e.digits, got, e.parity)
		}
	}
}

// Invariant 3: Maps exactly 81 chunks to each parity nibble.
// Each lane digit ranges over 0..5, three odd and three even, so every 4-bit
// parity pattern is hit by exactly 3^4 chunks.
func TestLaneChunkTableHitsEveryNibbleEqually(t *testing.T) {
	if chunkRadix != 1296 {
		t.Fatalf("chunk radix %d, want 6^4", chunkRadix)
	}
	counts := make(map[int]int)
	for c := 0; c < chunkRadix; c++ {
		counts[chunkParity(c)]++
	}
	for nibble := 0; nibble < 16; nibble++ {
		if counts[nibble] != 81 {
			t.Fatalf("nibble %04b appears %d times, want 81", nibble, counts[nibble])
		}
	}
	if len(counts) != 16 {
		t.Fatalf("chunk table produces %d distinct values, want 16", len(counts))
	}
}

// Invariant 4: Shares lookup tables across cipher instances.
func TestSpreadTablesAreSharedAcrossGadgets(t *testing.T) {
	counts := make([]int, 3)
	for streams := 1; streams < len(counts); streams++ {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &sharedTablesCircuit{streams: streams})
		if err != nil {
			t.Fatal(err)
		}
		counts[streams] = cs.GetNbConstraints()
	}
	single := compilePath(t, 16).GetNbConstraints()
	t.Logf("one CTR stream %d constraints, two streams %d, second stream adds %d", counts[1], counts[2], counts[2]-counts[1])
	if counts[2]-counts[1] >= single-int(substitutionSize+tableRegionSize+chunkRadix) {
		t.Fatalf("second gadget did not reuse the spread tables")
	}
}

// Invariant 5: Rejects forged results in each lookup table.
func TestLookupTablesRejectForgedResultAtValidIndex(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &lookupForgeryCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(&lookupForgeryCircuit{SubstitutionIndex: 0x3c, ByteIndex: 0xa5, ChunkIndex: 777}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(witness); err != nil {
		t.Fatal(err)
	}
	for name, size := range map[string]uint64{"substitution": substitutionSize, "bytes": tableRegionSize, "chunks": chunkRadix} {
		t.Run(name, func(t *testing.T) {
			forged := hintattack.ForgeLookupResult(t, cs, size)
			hintattack.RequireConstraintRejection(t, cs.IsSolved(witness, hintattack.SkipMissingLookupQueries(t)))
			if forged.Load() != 1 {
				t.Fatalf("forged %d lookups, want exactly one", forged.Load())
			}
		})
	}
}

// Invariant 6: Rejects chunks that do not recompose the input.
func TestLaneChunksMustRecomposeTheirInput(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &laneRecompositionCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	honest, err := frontend.NewWitness(&laneRecompositionCircuit{Sum: 1, Byte: 1}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(honest); err != nil {
		t.Fatal(err)
	}
	bad, err := frontend.NewWitness(&laneRecompositionCircuit{Sum: 1, Byte: 0}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	forge := func(_ *big.Int, _, outputs []*big.Int) error {
		for _, out := range outputs {
			out.SetInt64(0)
		}
		return nil
	}
	hintattack.RequireConstraintRejection(t, cs.IsSolved(bad, solver.OverrideHint(solver.GetHintID(laneChunksHint), forge)))
}

// Invariant 6: Rejects forged chunks during CTR encryption.
func TestCompiledSpreadCTRRejectsForgedLaneChunks(t *testing.T) {
	cs := compilePath(t, 16)
	honest, _ := ctrAssignment(t, 16)
	witness, err := frontend.NewWitness(honest, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(witness); err != nil {
		t.Fatal(err)
	}
	hintattack.SubstituteOutOfRangeLookups(t, cs, 0)
	skipMissing := hintattack.SkipMissingLookupQueries(t)
	forgeries := map[string]func(field *big.Int, chunks []*big.Int){
		"lane chunk borrowed from its upper neighbour": func(field *big.Int, chunks []*big.Int) {
			chunks[0].Add(chunks[0], big.NewInt(chunkRadix))
			chunks[1].Sub(chunks[1], big.NewInt(1))
			chunks[1].Mod(chunks[1], field)
		},
		"lane chunk shifted by one": func(field *big.Int, chunks []*big.Int) {
			chunks[0].Add(chunks[0], big.NewInt(1))
		},
		"lane chunk wrapped below zero": func(field *big.Int, chunks []*big.Int) {
			chunks[0].Sub(chunks[0], big.NewInt(chunkRadix))
			chunks[0].Mod(chunks[0], field)
			chunks[1].Add(chunks[1], big.NewInt(1))
		},
	}
	for name, forge := range forgeries {
		forged := func(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
			if err := laneChunksHint(field, inputs, outputs); err != nil {
				return err
			}
			forge(field, outputs)
			return nil
		}
		t.Run(name, func(t *testing.T) {
			hintattack.RequireConstraintRejection(t, cs.IsSolved(witness, solver.OverrideHint(solver.GetHintID(laneChunksHint), forged), skipMissing))
		})
	}
}

// Invariant 7: Demonstrates why recomposition and membership are both necessary.
func TestLaneParityChecksEachStopTheirAttack(t *testing.T) {
	zeroed := func(chunks []*big.Int) {
		for _, c := range chunks {
			c.SetInt64(0)
		}
	}
	wholeSumInChunkZero := func(chunks []*big.Int) {
		chunks[0].SetInt64(chunkRadix)
		chunks[1].SetInt64(0)
	}
	cases := []struct {
		name            string
		mutant          laneParityMutation
		lane            int64
		honest, claimed int64
		forge           func([]*big.Int)
	}{
		{"recomposition stops zeroed chunks", laneParityWithoutRecomposition, 1, 1, 0, zeroed},
		{"membership stops an oversized chunk", laneParityWithoutChunkMembership, chunkRadix, 16, 0, wholeSumInChunkZero},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := solveLaneParityMutant(t, tc.mutant, tc.lane, tc.honest, func([]*big.Int) {}, false); err != nil {
				t.Fatalf("mutant rejects the honest witness: %v", err)
			}
			hintattack.RequireConstraintRejection(t, solveLaneParityMutant(t, laneParityIntact, tc.lane, tc.claimed, tc.forge, true))
			if err := solveLaneParityMutant(t, tc.mutant, tc.lane, tc.claimed, tc.forge, false); err != nil {
				t.Fatalf("mutant still rejects the attack, so the removed check is not what stops it: %v", err)
			}
		})
	}
}

// Invariant 8: Requires byte bounds to prevent substitution-region escape.
func TestSubstituteRegionEscapeNeedsByteIndex(t *testing.T) {
	solve := func(guarded bool, opts ...solver.Option) error {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &substituteEscapeCircuit{guarded: guarded})
		if err != nil {
			t.Fatal(err)
		}
		witness, err := frontend.NewWitness(&substituteEscapeCircuit{Index: tableRegionSize}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if guarded {
			hintattack.SubstituteOutOfRangeLookups(t, cs, 0)
			opts = append(opts, hintattack.SkipMissingLookupQueries(t))
		}
		return cs.IsSolved(witness, opts...)
	}
	if err := solve(false); err != nil {
		t.Fatalf("an unconstrained index must escape into the next region: %v", err)
	}
	hintattack.RequireConstraintRejection(t, solve(true))
}

// Test circuits and shared helpers.

type spreadBytePropertyCircuit struct {
	Bytes    [256]frontend.Variable
	Expected [256]frontend.Variable
}

func (c *spreadBytePropertyCircuit) Define(api frontend.API) error {
	tables := sharedSpreadTables(api)
	// Every populated table needs a query, including the unused AES S-box.
	tables.substitute(sboxRegion, c.Bytes[0])
	for i, value := range c.Bytes {
		spread := tables.spreadByte(value)
		api.AssertIsEqual(spread, c.Expected[i])
		api.AssertIsEqual(tables.decodeWordSum(spread, 1)[0], value)
	}
	return nil
}

func solveSpreadCircuit(t *testing.T, cs constraint.ConstraintSystem, assignment frontend.Circuit) error {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return cs.IsSolved(witness)
}

type spreadXORPropertyCircuit struct {
	Bytes [5]frontend.Variable
	XOR   [5]frontend.Variable
}

func (c *spreadXORPropertyCircuit) Define(api frontend.API) error {
	tables := sharedSpreadTables(api)
	// Every populated table needs a query, including the unused AES S-box.
	tables.substitute(sboxRegion, c.Bytes[0])
	var sum frontend.Variable = 0
	for i, value := range c.Bytes {
		sum = api.Add(sum, tables.spreadByte(value))
		api.AssertIsEqual(tables.decodeWordSum(sum, 1)[0], c.XOR[i])
	}
	return nil
}

func spreadXORAssignment(bytes [5]byte) *spreadXORPropertyCircuit {
	assignment := new(spreadXORPropertyCircuit)
	var xor byte
	for i, value := range bytes {
		xor ^= value
		assignment.Bytes[i] = value
		assignment.XOR[i] = xor
	}
	return assignment
}

type sharedTablesCircuit struct {
	streams    int
	Key        [32]frontend.Variable
	Nonce      [12]frontend.Variable
	Plaintext  [16]frontend.Variable
	Ciphertext [16]frontend.Variable `gnark:",public"`
}

func (c *sharedTablesCircuit) Define(api frontend.API) error {
	for s := 0; s < c.streams; s++ {
		ciphertext := NewCipher(api, c.Key).CTREncrypt(c.Nonce, c.Plaintext[:])
		for i := range ciphertext {
			api.AssertIsEqual(ciphertext[i], c.Ciphertext[i])
		}
	}
	return nil
}

type lookupForgeryCircuit struct {
	SubstitutionIndex, ByteIndex, ChunkIndex frontend.Variable
}

func (c *lookupForgeryCircuit) Define(api frontend.API) error {
	t := sharedSpreadTables(api)
	t.substitute(0, c.SubstitutionIndex)
	t.spreadByte(c.ByteIndex)
	t.chunks.Lookup(c.ChunkIndex)
	return nil
}

type laneRecompositionCircuit struct {
	Sum, Byte frontend.Variable
}

func (c *laneRecompositionCircuit) Define(api frontend.API) error {
	t := sharedSpreadTables(api)
	// Each populated table needs a query, including the tables unused by this
	// isolated lane check. Sum=1 fixes the expected byte to one.
	api.AssertIsEqual(t.spreadByte(c.Sum), t.spreadConstant(1))
	api.AssertIsEqual(t.substitute(sboxRegion, c.Sum), t.spreadConstant(sbox0[1]))
	api.AssertIsEqual(t.decodeWordSum(c.Sum, 1)[0], c.Byte)
	return nil
}

type laneParityMutation uint8

const (
	laneParityIntact laneParityMutation = iota
	laneParityWithoutRecomposition
	laneParityWithoutChunkMembership
)

func init() {
	solver.RegisterHint(chunkParityHint)
}

func chunkParityHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != len(outputs) {
		return fmt.Errorf("chunk parity: %d inputs for %d outputs", len(inputs), len(outputs))
	}
	for i, chunk := range inputs {
		if !chunk.IsInt64() {
			return fmt.Errorf("chunk parity: chunk %d is not an integer", i)
		}
		outputs[i].SetInt64(int64(chunkParity(int(chunk.Int64()))))
	}
	return nil
}

func decodeWordSumMutant(t *spreadTables, spreadSum frontend.Variable, byteCount int, mutation laneParityMutation) []frontend.Variable {
	out := make([]frontend.Variable, byteCount)
	chunks, err := t.api.NewHint(laneChunksHint, 2*byteCount, spreadSum)
	if err != nil {
		panic(err)
	}
	if mutation != laneParityWithoutRecomposition {
		var recomposed frontend.Variable = 0
		weight := big.NewInt(1)
		for _, c := range chunks {
			recomposed = t.api.Add(recomposed, t.api.Mul(c, weight))
			weight = new(big.Int).Mul(weight, big.NewInt(chunkRadix))
		}
		t.api.AssertIsEqual(spreadSum, recomposed)
	}
	var nibbles []frontend.Variable
	if mutation == laneParityWithoutChunkMembership {
		nibbles, err = t.api.NewHint(chunkParityHint, len(chunks), chunks...)
		if err != nil {
			panic(err)
		}
	} else {
		nibbles = t.chunks.Lookup(chunks...)
	}
	for j := range out {
		out[j] = t.api.Add(nibbles[2*j], t.api.Mul(nibbles[2*j+1], 16))
	}
	return out
}

type laneParityMutantCircuit struct {
	Lane, Byte frontend.Variable
	mutation   laneParityMutation
}

func (c *laneParityMutantCircuit) Define(api frontend.API) error {
	t := sharedSpreadTables(api)
	t.spreadByte(1)
	t.substitute(sboxRegion, 1)
	if c.mutation == laneParityWithoutChunkMembership {
		t.chunks.Lookup(1)
	}
	api.AssertIsEqual(decodeWordSumMutant(t, c.Lane, 1, c.mutation)[0], c.Byte)
	return nil
}

func solveLaneParityMutant(t *testing.T, mutation laneParityMutation, lane, claimed int64, forge func(chunks []*big.Int), rejecting bool) error {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &laneParityMutantCircuit{mutation: mutation})
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(&laneParityMutantCircuit{Lane: lane, Byte: claimed}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	forged := func(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
		if err := laneChunksHint(field, inputs, outputs); err != nil {
			return err
		}
		forge(outputs)
		return nil
	}
	opts := []solver.Option{solver.OverrideHint(solver.GetHintID(laneChunksHint), forged)}
	if rejecting {
		hintattack.SubstituteOutOfRangeLookups(t, cs, 0)
		opts = append(opts, hintattack.SkipMissingLookupQueries(t))
	}
	return cs.IsSolved(witness, opts...)
}

type substituteEscapeCircuit struct {
	Index   frontend.Variable
	guarded bool
}

func (c *substituteEscapeCircuit) Define(api frontend.API) error {
	t := sharedSpreadTables(api)
	t.spreadByte(1)
	t.chunks.Lookup(1)
	if c.guarded {
		t.spreadByte(c.Index)
	}
	api.AssertIsEqual(t.substitute(0, c.Index), t.substitute(1, 0))
	return nil
}
