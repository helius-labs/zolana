// Tested Poseidon KDF invariants:
//
//  1. Keys and nonces match the reference at info-length and field boundaries;
//     altered key and nonce bytes are rejected.
//  2. Info with a leading zero in its final chunk or more than 434 bytes is
//     rejected during compilation.
//  3. Valid secret tags encode as big-endian integers; leading zeros and tags
//     longer than 31 bytes are rejected.
package verifiableencryption_test

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/require"

	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/prover-test/hintattack"
)

// Invariant 1: Matches reference keys and nonces at info and field boundaries; rejects altered outputs.
func TestKeyScheduleMatchesReferenceAtBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, 30, 31, 32, 62, 63, 434} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			info := bytes.Repeat([]byte{0xa5}, size)
			// Leading zeros in an earlier, fixed-width chunk remain unambiguous.
			if size > 31 {
				info[0] = 0
			}
			cs := compileGadget(t, &keyScheduleCircuit{info: info})
			for _, secret := range []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))} {
				key, nonce := referenceKeySchedule(t, secret, info)
				w := &keyScheduleCircuit{Secret: secret}
				for i, b := range key {
					w.Key[i] = b
				}
				for i, b := range nonce {
					w.Nonce[i] = b
				}
				if err := solveCompiled(t, cs, w); err != nil {
					t.Fatal(err)
				}
				w.Key[0] = key[0] ^ 1
				hintattack.RequireConstraintRejection(t, solveCompiled(t, cs, w))
				w.Key[0] = key[0]
				w.Nonce[11] = nonce[11] ^ 1
				hintattack.RequireConstraintRejection(t, solveCompiled(t, cs, w))
			}
		})
	}
}

// Invariant 2: Rejects a leading zero in the final info chunk and info longer than 434 bytes.
func TestKeyScheduleRejectsAmbiguousInfo(t *testing.T) {
	for _, prefixChunks := range []int{0, 1, 13} {
		for _, tailSize := range []int{1, 2, 30, 31} {
			t.Run(fmt.Sprintf("prefix_%d_tail_%d", prefixChunks, tailSize), func(t *testing.T) {
				info := bytes.Repeat([]byte{0xa5}, 31*prefixChunks+tailSize)
				info[31*prefixChunks] = 0
				_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &keyScheduleCircuit{info: info})
				if err == nil || !strings.Contains(err.Error(), "kdf: final info chunk must not start with zero") {
					t.Fatalf("want ambiguous info rejected at compilation, got %v", err)
				}
			})
		}
	}
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &keyScheduleCircuit{info: bytes.Repeat([]byte{1}, 435)})
	if err == nil || !strings.Contains(err.Error(), "kdf: info of 435 bytes, at most 434") {
		t.Fatalf("want oversized info rejected at compilation, got %v", err)
	}
}

// Invariant 3: Encodes valid secret tags as big-endian integers; rejects leading zeros and tags over 31 bytes.
func TestSecretTagCanonicalEncoding(t *testing.T) {
	for _, tag := range [][]byte{nil, {}, {'A'}, {'A', 0}, bytes.Repeat([]byte{0xff}, 31)} {
		if ve.SecretTagValue(tag).Cmp(new(big.Int).SetBytes(tag)) != 0 {
			t.Fatalf("tag %x changed its value", tag)
		}
	}
	for _, tag := range [][]byte{{0}, {0, 'A'}, append([]byte{0}, bytes.Repeat([]byte{1}, 30)...)} {
		require.PanicsWithValue(t, "ecies: secret tag must not start with zero", func() { ve.SecretTagValue(tag) })
	}
	require.PanicsWithValue(t, "ecies: secret tag of 32 bytes, at most 31", func() { ve.SecretTagValue(bytes.Repeat([]byte{1}, 32)) })
}

// Test circuits and shared helpers.

type keyScheduleCircuit struct {
	Secret frontend.Variable
	Key    [32]frontend.Variable `gnark:",public"`
	Nonce  [12]frontend.Variable `gnark:",public"`
	info   []byte
}

func (c *keyScheduleCircuit) Define(api frontend.API) error {
	key, nonce := ve.KeySchedule(api, c.Secret, c.info)
	for i, b := range key {
		api.AssertIsEqual(b, c.Key[i])
	}
	for i, b := range nonce {
		api.AssertIsEqual(b, c.Nonce[i])
	}
	return nil
}

// Use the full-arity reference here, including 16-input Poseidon for 434-byte info.
func referenceKeySchedule(t *testing.T, secret *big.Int, info []byte) (key [32]byte, nonce [12]byte) {
	t.Helper()
	hash := func(inputs ...*big.Int) *big.Int {
		h, err := poseidon.Hash(inputs)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	inputs := []*big.Int{new(big.Int).SetUint64(uint64(ve.DomSepSilo)), secret}
	for start := 0; start < len(info); start += 31 {
		inputs = append(inputs, new(big.Int).SetBytes(info[start:min(start+31, len(info))]))
	}
	silo := hash(inputs...)
	lo := hash(new(big.Int).SetUint64(uint64(ve.DomSepKey)), silo).FillBytes(make([]byte, 32))
	hi := hash(new(big.Int).SetUint64(uint64(ve.DomSepKey+1)), silo).FillBytes(make([]byte, 32))
	n := hash(new(big.Int).SetUint64(uint64(ve.DomSepNonce)), silo).FillBytes(make([]byte, 32))
	copy(key[:16], hi[16:])
	copy(key[16:], lo[16:])
	copy(nonce[:], n[20:])
	return key, nonce
}
