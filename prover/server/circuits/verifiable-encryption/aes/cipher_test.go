// Tested cipher invariants:
//
//  1. AES-256-CTR starting at nonce || 0x00000002 matches Go's AES implementation
//     and the ciphertext portions of GCM known-answer vectors.
//  2. Empty inputs, full blocks, and partial tails produce the expected ciphertext.
//  3. Altered ciphertext is rejected by compiled constraints and the test engine.
//  4. Key, nonce, and plaintext values outside 0..255 are rejected, even with
//     adversarial lookup outputs.
//  5. Cached counter processing matches AES across every counter-byte carry
//     and when returning to an earlier counter.
//  6. Reusing a Cipher across streams preserves correctness, rejects altered
//     outputs, and uses fewer constraints than separate key expansions.
//  7. A forged key-byte spread lookup is rejected even when the claimed
//     ciphertext matches the substituted key.
package aes

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"zolana/prover/prover-test/hintattack"
)

// Invariant 1: Matches Go AES-256-CTR.
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

// Invariant 1: Matches known-answer ciphertexts.
func TestCTREncryptMatchesGCMKnownAnswers(t *testing.T) {
	for _, row := range []struct {
		name       string
		key        string
		nonce      string
		plaintext  string
		ciphertext string
	}{
		{
			"GCM test case 14",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"000000000000000000000000",
			"00000000000000000000000000000000",
			"cea7403d4d606b6e074ec5d3baf39d18",
		},
		{
			"GCM test case 15",
			"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
			"cafebabefacedbaddecaf888",
			"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
			"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
		},
		{
			"GCM test case 16",
			"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
			"cafebabefacedbaddecaf888",
			"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			plaintext := mustHex(t, row.plaintext)
			assignment := &pathCtrCircuit{Plaintext: toVariables(plaintext), Ciphertext: toVariables(mustHex(t, row.ciphertext))}
			copy(assignment.Key[:], toVariables(mustHex(t, row.key)))
			copy(assignment.Nonce[:], toVariables(mustHex(t, row.nonce)))
			witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := compilePath(t, len(plaintext)).IsSolved(witness); err != nil {
				t.Fatalf("known answer rejected: %v", err)
			}
		})
	}
}

// Invariant 2: Handles empty inputs, full blocks, and partial tails.
func TestCTRLengthsMatchHost(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 4, 7, 15, 17, 31, 32, 33, 63, 4097} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			key, nonce, plain := ctrPattern(32, 0xa5), ctrPattern(12, 0x5a), ctrPattern(n, 7)
			w := &pathCtrCircuit{Plaintext: toVariables(plain), Ciphertext: toVariables(hostCtr(t, key, nonce, plain))}
			copy(w.Key[:], toVariables(key))
			copy(w.Nonce[:], toVariables(nonce))
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := compilePath(t, n).IsSolved(witness); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Invariant 3: Compiled constraints reject altered ciphertext.
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

// Invariant 3: The test engine rejects altered ciphertext.
func TestSpreadCTRRejectsTamperedCiphertextUnderTestEngine(t *testing.T) {
	assignment, ciphertext := ctrAssignment(t, 48)
	ciphertext[17] ^= 0x80
	assignment.Ciphertext = toVariables(ciphertext)
	circuit := &pathCtrCircuit{Plaintext: make([]frontend.Variable, 48), Ciphertext: make([]frontend.Variable, 48)}
	if test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()) == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

// Invariant 4: Rejects out-of-range key, nonce, and plaintext bytes.
func TestCTRRejectsOutOfRangeBytes(t *testing.T) {
	const n = 17
	cs := compilePath(t, n)
	substituted := hintattack.SubstituteOutOfRangeLookups(t, cs, 0)
	skipMissing := hintattack.SkipMissingLookupQueries(t)
	key, nonce, plain := ctrPattern(32, 0xa5), ctrPattern(12, 0x5a), ctrPattern(n, 7)
	for _, part := range []string{"key", "nonce", "plaintext"} {
		t.Run(part, func(t *testing.T) {
			// The claimed ciphertext matches byte zero returned by the adversarial
			// lookup solver, leaving the byte's table membership to reject it.
			k, iv, p := slices.Clone(key), slices.Clone(nonce), slices.Clone(plain)
			switch part {
			case "key":
				k[0] = 0
			case "nonce":
				iv[0] = 0
			case "plaintext":
				p[0] = 0
			}
			w := &pathCtrCircuit{Plaintext: toVariables(p), Ciphertext: toVariables(hostCtr(t, k, iv, p))}
			copy(w.Key[:], toVariables(k))
			copy(w.Nonce[:], toVariables(iv))
			solve := func() error {
				witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				return cs.IsSolved(witness, skipMissing)
			}
			substituted.Store(0)
			if err := solve(); err != nil {
				t.Fatal(err)
			}
			if substituted.Load() != 0 {
				t.Fatal("honest input needed a substituted lookup")
			}
			for _, bad := range []int{256, -1} {
				switch part {
				case "key":
					w.Key[0] = bad
				case "nonce":
					w.Nonce[0] = bad
				case "plaintext":
					w.Plaintext[0] = bad
				}
				substituted.Store(0)
				hintattack.RequireConstraintRejection(t, solve())
				if substituted.Load() == 0 {
					t.Fatal("invalid byte did not reach the adversarial lookup solver")
				}
			}
		})
	}
}

// Invariant 5: Preserves correctness across counter carries and cache refreshes.
func TestCounterCarryCacheMatchesAES(t *testing.T) {
	counters := []uint32{2, 3, 254, 255, 256, 257, 65535, 65536, 65537, 0xffffff, 0x1000000, 0xffffffff, 2}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &counterSequenceCircuit{
		counters: counters, Ciphertext: make([]frontend.Variable, 16*len(counters)),
	})
	if err != nil {
		t.Fatal(err)
	}
	key, nonce := ctrPattern(32, 0xa5), ctrPattern(12, 0x5a)
	w := &counterSequenceCircuit{Ciphertext: make([]frontend.Variable, 16*len(counters))}
	copy(w.Key[:], toVariables(key))
	copy(w.Nonce[:], toVariables(nonce))
	block, err := stdaes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	for j, counter := range counters {
		var in, out [16]byte
		copy(in[:], nonce)
		binary.BigEndian.PutUint32(in[12:], counter)
		block.Encrypt(out[:], in[:])
		copy(w.Ciphertext[j*16:], toVariables(out[:]))
	}
	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(witness); err != nil {
		t.Fatal(err)
	}
}

// Invariant 6: Reuses key expansion while constraining every stream.
func TestCipherReusesKeyExpansionAcrossStreams(t *testing.T) {
	key := ctrPattern(32, 0xa5)
	w := &reusableCipherCircuit{}
	copy(w.Key[:], toVariables(key))
	for i := range w.Nonce {
		nonce, plain := ctrPattern(12, byte(i)), ctrPattern(16, byte(i+1))
		copy(w.Nonce[i][:], toVariables(nonce))
		copy(w.Plaintext[i][:], toVariables(plain))
		copy(w.Ciphertext[i][:], toVariables(hostCtr(t, key, nonce, plain)))
	}
	var counts [2]int
	for i, reuse := range []bool{false, true} {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &reusableCipherCircuit{reuse: reuse})
		if err != nil {
			t.Fatal(err)
		}
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(witness); err != nil {
			t.Fatal(err)
		}
		counts[i] = cs.GetNbConstraints()
		for stream := range w.Ciphertext {
			honest := w.Ciphertext[stream][15]
			w.Ciphertext[stream][15] = honest.(byte) ^ 1
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			hintattack.RequireConstraintRejection(t, cs.IsSolved(witness))
			w.Ciphertext[stream][15] = honest
		}
	}
	if counts[1] >= counts[0] {
		t.Fatalf("key expansion reuse did not save constraints: separate %d, reused %d", counts[0], counts[1])
	}
	t.Logf("two streams: separate %d constraints, reused %d, saved %d", counts[0], counts[1], counts[0]-counts[1])
}

// Invariant 7: Rejects a forged key-byte spread lookup.
func TestCTRRejectsForgedKeyByteSpread(t *testing.T) {
	const n = 16
	cs := compilePath(t, n)
	key, nonce, plain := ctrPattern(32, 0xa5), ctrPattern(12, 0x5a), ctrPattern(n, 7)
	flipped := slices.Clone(key)
	flipped[0] ^= 1
	assignment := func(k []byte) *pathCtrCircuit {
		w := &pathCtrCircuit{Plaintext: toVariables(plain), Ciphertext: toVariables(hostCtr(t, flipped, nonce, plain))}
		copy(w.Key[:], toVariables(k))
		copy(w.Nonce[:], toVariables(nonce))
		return w
	}
	solve := func(w *pathCtrCircuit, opts ...solver.Option) error {
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		return cs.IsSolved(witness, opts...)
	}
	if err := solve(assignment(flipped)); err != nil {
		t.Fatal(err)
	}
	failingConstraint := func(err error) int {
		var unsatisfied *cs_bn254.UnsatisfiedConstraintError
		if !errors.As(err, &unsatisfied) {
			t.Fatalf("stopped outside a constraint: %v", err)
		}
		return unsatisfied.CID
	}
	control := solve(assignment(key))
	hintattack.RequireConstraintRejection(t, control)

	forged := hintattack.ForgeLookupResult(t, cs, tableRegionSize)
	attack := solve(assignment(key), hintattack.SkipMissingLookupQueries(t))
	hintattack.RequireConstraintRejection(t, attack)
	if forged.Load() != 1 {
		t.Fatalf("forged %d lookups, want exactly one", forged.Load())
	}
	if failingConstraint(attack) <= failingConstraint(control) {
		t.Fatalf("forged run failed at constraint %d, not after the ciphertext check at %d", failingConstraint(attack), failingConstraint(control))
	}
}

// Test circuits and shared helpers.

type roundKeysCtrCircuit struct {
	Key        [32]frontend.Variable
	Nonce      [12]frontend.Variable
	Plaintext  []frontend.Variable
	Ciphertext []frontend.Variable `gnark:",public"`
}

func (c *roundKeysCtrCircuit) Define(api frontend.API) error {
	ciphertext := NewCipher(api, c.Key).CTREncrypt(c.Nonce, c.Plaintext)
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

type pathCtrCircuit struct {
	Key        [32]frontend.Variable
	Nonce      [12]frontend.Variable
	Plaintext  []frontend.Variable
	Ciphertext []frontend.Variable `gnark:",public"`
}

func (c *pathCtrCircuit) Define(api frontend.API) error {
	ciphertext := NewCipher(api, c.Key).CTREncrypt(c.Nonce, c.Plaintext)
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

type reusableCipherCircuit struct {
	Key        [32]frontend.Variable
	Nonce      [2][12]frontend.Variable
	Plaintext  [2][16]frontend.Variable
	Ciphertext [2][16]frontend.Variable `gnark:",public"`
	reuse      bool
}

func (c *reusableCipherCircuit) Define(api frontend.API) error {
	var cipher *Cipher
	if c.reuse {
		cipher = NewCipher(api, c.Key)
	}
	for stream := range c.Nonce {
		var ciphertext []frontend.Variable
		if c.reuse {
			ciphertext = cipher.CTREncrypt(c.Nonce[stream], c.Plaintext[stream][:])
		} else {
			ciphertext = NewCipher(api, c.Key).CTREncrypt(c.Nonce[stream], c.Plaintext[stream][:])
		}
		for i, b := range ciphertext {
			api.AssertIsEqual(b, c.Ciphertext[stream][i])
		}
	}
	return nil
}

func ctrPattern(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*73) ^ seed
	}
	return out
}

// Reach all counter-byte carries without constructing millions of AES blocks.
type counterSequenceCircuit struct {
	Key        [32]frontend.Variable
	Nonce      [12]frontend.Variable
	Ciphertext []frontend.Variable `gnark:",public"`
	counters   []uint32
}

func (c *counterSequenceCircuit) Define(api frontend.API) error {
	keys := expandRoundKeys(api, c.Key)
	nonce := make([]frontend.Variable, 12)
	for i, b := range c.Nonce {
		nonce[i] = keys.tables.spreadByte(b)
	}
	stream := &ctrStream{keys: keys, nonceState: keys.addRoundKey(nonce, 0), cachedHigh: -1}
	plaintextBytes := make([]frontend.Variable, 16)
	for i := range plaintextBytes {
		plaintextBytes[i] = 0
	}
	for j, counter := range c.counters {
		for i, b := range stream.encryptBlock(counter, plaintextBytes) {
			api.AssertIsEqual(b, c.Ciphertext[j*16+i])
		}
	}
	return nil
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
