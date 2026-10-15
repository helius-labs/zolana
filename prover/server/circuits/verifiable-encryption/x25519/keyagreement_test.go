package x25519

import (
	"bytes"
	nativeecdh "crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type agreeKeyCircuit struct {
	NoLookups         bool `gnark:"-"`
	Scalar, PublicKey [32]frontend.Variable
	Expected          [6]frontend.Variable `gnark:",public"`
}

func (c *agreeKeyCircuit) Define(api frontend.API) error {
	got := AgreeKeyFor(api, c.Scalar, c.PublicKey, !c.NoLookups)
	for i, v := range []frontend.Variable{got.RecipientLo, got.RecipientHi, got.EphemeralLo, got.EphemeralHi, got.SharedLo, got.SharedHi} {
		api.AssertIsEqual(v, c.Expected[i])
	}
	return nil
}

func agreeWitness(t *testing.T, scalar, peer []byte) *agreeKeyCircuit {
	t.Helper()
	sk, err := nativeecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := nativeecdh.X25519().NewPublicKey(peer)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := sk.ECDH(pk)
	if err != nil {
		t.Fatal(err)
	}
	w := new(agreeKeyCircuit)
	for i := range w.Scalar {
		w.Scalar[i], w.PublicKey[i] = scalar[i], peer[i]
	}
	for i, encoded := range [][]byte{peer, sk.PublicKey().Bytes(), shared} {
		w.Expected[2*i] = new(big.Int).SetBytes(encoded[:31])
		w.Expected[2*i+1] = new(big.Int).SetBytes(encoded[31:])
	}
	return w
}

func solveAgree(cs constraint.ConstraintSystem, w *agreeKeyCircuit) error {
	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	return cs.IsSolved(witness)
}

func TestAgreeKey(t *testing.T) {
	for _, plain := range []bool{false, true} {
		t.Run(fmt.Sprintf("noLookups=%v", plain), func(t *testing.T) {
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &agreeKeyCircuit{NoLookups: plain})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("full key agreement: %d constraints", cs.GetNbConstraints())
			if plain {
				if commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments); ok && len(commitments) != 0 {
					t.Fatal("plain agreement added lookup commitment")
				}
			}
			for _, u := range []int64{2, 9} {
				for _, scalarByte := range []byte{0, 0xff, 0x55} {
					s := bytes.Repeat([]byte{scalarByte}, 32)
					peer := littleEndian(big.NewInt(u))
					w := agreeWitness(t, s, peer)
					if err := solveAgree(cs, w); err != nil {
						t.Fatalf("u%d scalar%x: %v", u, scalarByte, err)
					}
				}
			}
			s := sha256.Sum256([]byte("X25519 full key agreement bindings"))
			peer := littleEndian(big.NewInt(9))
			w := agreeWitness(t, s[:], peer)
			for field := range w.Expected {
				bad := *w
				bad.Expected[field] = new(big.Int).Add(w.Expected[field].(*big.Int), big.NewInt(1))
				if solveAgree(cs, &bad) == nil {
					t.Fatalf("accepted modified packed field%d", field)
				}
			}
			bad := *w
			bad.Scalar[1] = byte(s[1] ^ 1)
			if solveAgree(cs, &bad) == nil {
				t.Fatal("scalar not bound to ephemeral/shared result")
			}
			bad = *w
			bad.PublicKey[0] = 10
			if solveAgree(cs, &bad) == nil {
				t.Fatal("recipient not bound")
			}
			for _, which := range []string{"scalar", "peer"} {
				for _, index := range []int{0, 15, 31} {
					bad = *w
					if which == "scalar" {
						bad.Scalar[index] = int(s[index]) + 256
					} else {
						bad.PublicKey[index] = int(peer[index]) + 256
					}
					if solveAgree(cs, &bad) == nil {
						t.Fatalf("accepted out-of-range %s byte%d", which, index)
					}
				}
			}
			for _, alias := range [][]byte{
				littleEndian(new(big.Int).Add(prime(), big.NewInt(9))),
				func() []byte { v := bytes.Clone(peer); v[31] |= 128; return v }(),
			} {
				aliased := agreeWitness(t, s[:], alias)
				if err := solveAgree(cs, aliased); err != nil {
					t.Fatalf("alias: %v", err)
				}
				for i := 2; i < 6; i++ {
					if aliased.Expected[i].(*big.Int).Cmp(w.Expected[i].(*big.Int)) != 0 {
						t.Fatal("alias changed ephemeral/shared result")
					}
				}
				aliased.Expected[0], aliased.Expected[1] = w.Expected[0], w.Expected[1]
				if solveAgree(cs, aliased) == nil {
					t.Fatal("recipient alias was not bound to its original encoding")
				}
			}
			ignored := bytes.Clone(s[:])
			ignored[0] ^= 7
			ignored[31] ^= 0xc0
			if err := solveAgree(cs, agreeWitness(t, ignored, peer)); err != nil {
				t.Fatalf("ignored scalar bits: %v", err)
			}
			for _, u := range []int64{0, 1} {
				bad = *w
				low := littleEndian(big.NewInt(u))
				for i := range bad.PublicKey {
					bad.PublicKey[i] = low[i]
				}
				bad.Expected[0] = new(big.Int).SetBytes(low[:31])
				bad.Expected[1] = new(big.Int).SetBytes(low[31:])
				bad.Expected[4], bad.Expected[5] = 0, 0
				if solveAgree(cs, &bad) == nil {
					t.Fatal("accepted low-order agreement")
				}
			}
		})
	}
}
