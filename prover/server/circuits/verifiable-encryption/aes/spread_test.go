package aes

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"zolana/prover/prover-test/hintattack"
)

type roundKeysCtrCircuit struct {
	Key        [32]frontend.Variable
	Nonce      [12]frontend.Variable
	Plaintext  []frontend.Variable
	Ciphertext []frontend.Variable `gnark:",public"`
}

func (c *roundKeysCtrCircuit) Define(api frontend.API) error {
	ciphertext := CTREncrypt(api, c.Key, c.Nonce, c.Plaintext)
	for i := range ciphertext {
		api.AssertIsEqual(ciphertext[i], c.Ciphertext[i])
	}
	return nil
}

func hostCtr(t *testing.T, key, nonce, plaintext []byte) []byte {
	t.Helper()
	block, err := stdaes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	iv := append(append([]byte{}, nonce...), 0, 0, 0, 2)
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		t.Fatal(err)
	}
	return out
}

func toVariables(bytes []byte) []frontend.Variable {
	out := make([]frontend.Variable, len(bytes))
	for i, b := range bytes {
		out[i] = b
	}
	return out
}

func TestCTREncryptAllPathsMatchHost(t *testing.T) {
	for _, n := range []int{16, 40, 48} {
		key := randomBytes(t, 32)
		nonce := randomBytes(t, 12)
		plaintext := randomBytes(t, n)
		expected := hostCtr(t, key, nonce, plaintext)

		circuit := &roundKeysCtrCircuit{
			Plaintext:  make([]frontend.Variable, n),
			Ciphertext: make([]frontend.Variable, n),
		}
		assignment := &roundKeysCtrCircuit{
			Plaintext:  toVariables(plaintext),
			Ciphertext: toVariables(expected),
		}
		copy(assignment.Key[:], toVariables(key))
		copy(assignment.Nonce[:], toVariables(nonce))
		if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
	}
}

type pathCtrCircuit struct {
	Key        [32]frontend.Variable
	Nonce      [12]frontend.Variable
	Plaintext  []frontend.Variable
	Ciphertext []frontend.Variable `gnark:",public"`
}

func (c *pathCtrCircuit) Define(api frontend.API) error {
	ciphertext := CTREncrypt(api, c.Key, c.Nonce, c.Plaintext)
	for i := range ciphertext {
		api.AssertIsEqual(ciphertext[i], c.Ciphertext[i])
	}
	return nil
}

func ctrAssignment(t *testing.T, n int) (*pathCtrCircuit, []byte) {
	t.Helper()
	key := randomBytes(t, 32)
	nonce := randomBytes(t, 12)
	plaintext := randomBytes(t, n)
	ciphertext := hostCtr(t, key, nonce, plaintext)
	assignment := &pathCtrCircuit{Plaintext: toVariables(plaintext), Ciphertext: toVariables(ciphertext)}
	copy(assignment.Key[:], toVariables(key))
	copy(assignment.Nonce[:], toVariables(nonce))
	return assignment, ciphertext
}

func compilePath(t *testing.T, n int) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &pathCtrCircuit{
		Plaintext:  make([]frontend.Variable, n),
		Ciphertext: make([]frontend.Variable, n),
	})
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func TestCompiledSpreadCTRAcceptsHonestAndRejectsTamperedCiphertext(t *testing.T) {
	for _, n := range []int{16, 40} {
		cs := compilePath(t, n)
		honest, ciphertext := ctrAssignment(t, n)
		witness, err := frontend.NewWitness(honest, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(witness); err != nil {
			t.Fatalf("%d bytes: honest witness rejected: %v", n, err)
		}
		for _, position := range []int{0, n - 1} {
			tampered := append([]byte{}, ciphertext...)
			tampered[position] ^= 1
			honest.Ciphertext = toVariables(tampered)
			witness, err := frontend.NewWitness(honest, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if cs.IsSolved(witness) == nil {
				t.Fatalf("%d bytes: ciphertext tampered at %d accepted", n, position)
			}
		}
	}
}

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

type sharedTablesCircuit struct {
	streams    int
	Key        [32]frontend.Variable
	Nonce      [12]frontend.Variable
	Plaintext  [16]frontend.Variable
	Ciphertext [16]frontend.Variable `gnark:",public"`
}

func (c *sharedTablesCircuit) Define(api frontend.API) error {
	for s := 0; s < c.streams; s++ {
		ciphertext := CTREncrypt(api, c.Key, c.Nonce, c.Plaintext[:])
		for i := range ciphertext {
			api.AssertIsEqual(ciphertext[i], c.Ciphertext[i])
		}
	}
	return nil
}

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

func TestSpreadCTRRejectsTamperedCiphertextUnderTestEngine(t *testing.T) {
	assignment, ciphertext := ctrAssignment(t, 48)
	ciphertext[17] ^= 0x80
	assignment.Ciphertext = toVariables(ciphertext)
	circuit := &pathCtrCircuit{Plaintext: make([]frontend.Variable, 48), Ciphertext: make([]frontend.Variable, 48)}
	if test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()) == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestLaneChunkTableKnownAnswers(t *testing.T) {
	// digits are the base-6 lane sums, least significant lane first; parity
	// carries bit i = digits[i] mod 2.
	entries := []struct {
		chunk  int
		digits [lanesPerChunk]int
		parity int
	}{
		{0, [lanesPerChunk]int{0, 0, 0, 0}, 0b0000},
		{1, [lanesPerChunk]int{1, 0, 0, 0}, 0b0001},
		{2, [lanesPerChunk]int{2, 0, 0, 0}, 0b0000},
		{5, [lanesPerChunk]int{5, 0, 0, 0}, 0b0001},
		{6, [lanesPerChunk]int{0, 1, 0, 0}, 0b0010},
		{7, [lanesPerChunk]int{1, 1, 0, 0}, 0b0011},
		{12, [lanesPerChunk]int{0, 2, 0, 0}, 0b0000},
		{36, [lanesPerChunk]int{0, 0, 1, 0}, 0b0100},
		{216, [lanesPerChunk]int{0, 0, 0, 1}, 0b1000},
		{259, [lanesPerChunk]int{1, 1, 1, 1}, 0b1111},
		{753, [lanesPerChunk]int{3, 5, 2, 3}, 0b1011},
		{1036, [lanesPerChunk]int{4, 4, 4, 4}, 0b0000},
		{1294, [lanesPerChunk]int{4, 5, 5, 5}, 0b1110},
		{1295, [lanesPerChunk]int{5, 5, 5, 5}, 0b1111},
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
