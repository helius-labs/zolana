package x25519

import (
	"crypto/sha256"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestBytePackingRejectsForgedHints(t *testing.T) {
	cs := compile(t, defaultLayout)
	scalar := sha256.Sum256([]byte("byte packing hostile hints"))
	peer := littleEndian(big.NewInt(9))
	shared, e := host(scalar[:], peer)
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range []struct {
		name     string
		original solver.Hint
		forge    solver.Hint
	}{
		{"split recomposition", splitByteHint, func(q *big.Int, in, out []*big.Int) error {
			if e := splitByteHint(q, in, out); e != nil {
				return e
			}
			out[1].Xor(out[1], big.NewInt(1))
			return nil
		}},
		{"split bounded pieces", splitByteHint, func(q *big.Int, in, out []*big.Int) error {
			if e := splitByteHint(q, in, out); e != nil {
				return e
			}
			out[0].Add(out[0], big.NewInt(1))
			out[1].Sub(out[1], bytePower(int(in[1].Int64())))
			return nil
		}},
		{"output value", outputBytesHint, func(q *big.Int, in, out []*big.Int) error {
			if e := outputBytesHint(q, in, out); e != nil {
				return e
			}
			out[0].Xor(out[0], big.NewInt(1))
			return nil
		}},
		{"output byte carry", outputBytesHint, func(q *big.Int, in, out []*big.Int) error {
			if e := outputBytesHint(q, in, out); e != nil {
				return e
			}
			out[0].Add(out[0], big.NewInt(256))
			out[1].Sub(out[1], big.NewInt(1))
			return nil
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := assignment(scalar[:], peer, shared)
			// Match the public result to the forged hint: rejection must come
			// from byte packing constraints, not the outer expected-value check.
			if row.name == "output value" {
				w.Shared[0] = shared[0] ^ 1
			}
			if row.name == "output byte carry" {
				w.Shared[0] = int(shared[0]) + 256
				w.Shared[1] = int(shared[1]) - 1
			}
			witness, e := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if e != nil {
				t.Fatal(e)
			}
			called := false
			replacement := func(q *big.Int, in, out []*big.Int) error { called = true; return row.forge(q, in, out) }
			e = cs.IsSolved(witness, solver.OverrideHint(solver.GetHintID(row.original), replacement))
			if !called {
				t.Fatal("forged hint not called")
			}
			if e == nil {
				t.Fatal("accepted forged hint")
			}
			if !strings.Contains(e.Error(), "is not satisfied") {
				t.Fatalf("expected constraint rejection, got %v", e)
			}
		})
	}
}

type canonicalKeyCircuit struct{ Key [32]frontend.Variable }

func (c *canonicalKeyCircuit) Define(api frontend.API) error {
	AssertCanonical(api, c.Key)
	return nil
}

func TestAssertCanonicalRejectsAliases(t *testing.T) {
	q := ecc.BN254.ScalarField()
	cs, err := frontend.Compile(q, r1cs.NewBuilder, &canonicalKeyCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	p := prime()
	for _, row := range []struct {
		value *big.Int
		ok    bool
	}{
		{big.NewInt(0), true},
		{big.NewInt(9), true},
		{new(big.Int).Sub(p, big.NewInt(1)), true},
		{p, false},
		{new(big.Int).Add(p, big.NewInt(9)), false},
		{new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1)), false},
		{new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(9)), false},
	} {
		var w canonicalKeyCircuit
		for i := range w.Key {
			w.Key[i] = new(big.Int).And(new(big.Int).Rsh(row.value, uint(8*i)), big.NewInt(0xff))
		}
		witness, err := frontend.NewWitness(&w, q)
		if err != nil {
			t.Fatal(err)
		}
		if got := cs.IsSolved(witness) == nil; got != row.ok {
			t.Fatalf("u=%s accepted=%v", row.value, got)
		}
	}
}
