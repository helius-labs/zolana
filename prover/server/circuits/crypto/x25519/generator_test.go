package x25519

import (
	"bytes"
	nativeecdh "crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type generatorCircuit struct {
	Scalar, PublicKey [32]frontend.Variable
}

func (c *generatorCircuit) Define(api frontend.API) error {
	got := ScalarMulGenerator(api, c.Scalar)
	for i := range got {
		api.AssertIsEqual(got[i], c.PublicKey[i])
	}
	return nil
}

func generatorWitness(t *testing.T, scalar []byte) *generatorCircuit {
	t.Helper()
	sk, err := nativeecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	w := new(generatorCircuit)
	for i, b := range sk.PublicKey().Bytes() {
		w.Scalar[i], w.PublicKey[i] = scalar[i], b
	}
	return w
}

func TestScalarMulGenerator(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &generatorCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fixed-base generation: %d constraints", cs.GetNbConstraints())
	solve := func(w *generatorCircuit, opts ...solver.Option) error {
		wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			return err
		}
		return cs.IsSolved(wit, opts...)
	}
	var cases [][]byte
	for _, v := range []byte{0, 0xff, 0x55, 0xaa} {
		cases = append(cases, bytes.Repeat([]byte{v}, 32))
	}
	// Set every bit of the last window and no lower bits. This
	// makes the final fixed-base addition a doubling of equal points.
	equal := make([]byte, 32)
	equal[31] = 0x7f // Seven-bit windows: top window has seven bits.

	cases = append(cases, equal)
	for i := 0; i < 20; i++ {
		s := sha256.Sum256([]byte(fmt.Sprintf("fixed-base public key %d", i)))
		cases = append(cases, bytes.Clone(s[:]))
	}
	for i, scalar := range cases {
		if err := solve(generatorWitness(t, scalar)); err != nil {
			t.Fatalf("case%d: %v", i, err)
		}
	}
	w := generatorWitness(t, cases[5])
	for _, index := range []int{0, 15, 31} {
		bad := *w
		bad.PublicKey[index] = byte(w.PublicKey[index].(byte) ^ 1)
		if solve(&bad) == nil {
			t.Fatal("accepted forged generated key")
		}
		for _, value := range []int{-1, 256} {
			bad = *w
			bad.Scalar[index] = value
			if solve(&bad) == nil {
				t.Fatal("accepted non-byte private key")
			}
		}
	}
	ignored := *w
	ignored.Scalar[0] = byte(w.Scalar[0].(byte) ^ 7)
	ignored.Scalar[31] = byte(w.Scalar[31].(byte) ^ 0xc0)
	if err := solve(&ignored); err != nil {
		t.Fatal("ignored bits changed generated key", err)
	}
	for _, suffix := range []string{"x25519.shortRatioHint", "x25519.baseFinalSlopeHint"} {
		found := false
		for _, original := range solver.GetRegisteredHints() {
			if !strings.HasSuffix(solver.GetHintName(original), suffix) {
				continue
			}
			found = true
			called := false
			bad := func(q *big.Int, in, out []*big.Int) error {
				if err := original(q, in, out); err != nil {
					return err
				}
				if !called {
					called = true
					out[0].Xor(out[0], big.NewInt(1))
				}
				return nil
			}
			err := solve(generatorWitness(t, equal), solver.OverrideHint(solver.GetHintID(original), bad))
			if err == nil || !called {
				t.Fatalf("%s forgery accepted or not exercised", suffix)
			}
			if !strings.Contains(err.Error(), "is not satisfied") {
				t.Fatalf("expected constraint rejection, got %v", err)
			}
		}
		if !found {
			t.Fatalf("missing hint%s", suffix)
		}
	}

}
