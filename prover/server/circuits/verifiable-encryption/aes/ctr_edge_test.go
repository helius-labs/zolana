package aes

import (
	stdaes "crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/prover/prover-test/hintattack"
)

func ctrPattern(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*73) ^ seed
	}
	return out
}

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
