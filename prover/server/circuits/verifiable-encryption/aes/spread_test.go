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
		if cs.IsSolved(witness, solver.OverrideHint(solver.GetHintID(laneChunksHint), forged)) == nil {
			t.Fatalf("%s: forged lane chunks accepted", name)
		}
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

func TestLaneChunkTableIsUniqueBase6ParityDigits(t *testing.T) {
	seen := make(map[int]int)
	for c := 0; c < chunkRadix; c++ {
		lanes := c
		expected := 0
		for lane := 0; lane < lanesPerChunk; lane++ {
			expected |= (lanes % chunkLaneBase & 1) << uint(lane)
			lanes /= chunkLaneBase
		}
		if lanes != 0 || chunkParity(c) != expected {
			t.Fatalf("chunk %d parity %d, expected %d", c, chunkParity(c), expected)
		}
		seen[expected]++
	}
	if len(seen) != 16 {
		t.Fatalf("chunk table covers %d nibbles", len(seen))
	}
}
