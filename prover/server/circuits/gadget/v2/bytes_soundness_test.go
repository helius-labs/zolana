package checked

import (
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type packedBytesCircuit struct {
	A, B, Expected frontend.Variable
}

func (c *packedBytesCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(BytesToField(api, []frontend.Variable{c.A, c.B}), c.Expected)
	return nil
}

type paddedBytesCircuit struct {
	Bytes    [32]frontend.Variable
	Expected frontend.Variable
}

func (c *paddedBytesCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(BytesToField(api, c.Bytes[:]), c.Expected)
	return nil
}

func TestBytesToFieldRejectsCarryBetweenBytes(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &packedBytesCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		w    packedBytesCircuit
		pass bool
	}{
		{"canonical", packedBytesCircuit{A: 1, B: 0, Expected: 256}, true},
		{"out-of-range alias", packedBytesCircuit{A: 0, B: 256, Expected: 256}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, err := frontend.NewWitness(&tc.w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if got := cs.IsSolved(w) == nil; got != tc.pass {
				t.Fatalf("solved = %v, want %v", got, tc.pass)
			}
		})
	}
}

func TestBytesToFieldRequiresZeroPrefixFor32Bytes(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &paddedBytesCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	valid := &paddedBytesCircuit{Expected: 1}
	for i := range valid.Bytes {
		valid.Bytes[i] = 0
	}
	valid.Bytes[31] = 1
	for _, tc := range []struct {
		name string
		w    *paddedBytesCircuit
		pass bool
	}{
		{"zero prefix", valid, true},
		{"nonzero prefix", func() *paddedBytesCircuit { w := *valid; w.Bytes[0] = 1; return &w }(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, err := frontend.NewWitness(tc.w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if got := cs.IsSolved(w) == nil; got != tc.pass {
				t.Fatalf("solved = %v, want %v", got, tc.pass)
			}
		})
	}
}

type canonicalFieldBytesCircuit struct {
	Value frontend.Variable
	Bytes [32]frontend.Variable
}

func (c *canonicalFieldBytesCircuit) Define(api frontend.API) error {
	encoded := FieldToBytesBE(api, c.Value)
	for i := range encoded {
		api.AssertIsEqual(encoded[i], c.Bytes[i])
	}
	return nil
}

// A native-field equality alone permits x and x+q. The byte boundary must
// reject the second encoding even when its bit hint supplies it consistently.
func TestFieldToBytesRejectsModulusAlias(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &canonicalFieldBytesCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	q := ecc.BN254.ScalarField()
	assignment := func(n *big.Int) *canonicalFieldBytesCircuit {
		a := &canonicalFieldBytesCircuit{Value: 7}
		var b [32]byte
		n.FillBytes(b[:])
		for i := range b {
			a.Bytes[i] = b[i]
		}
		return a
	}
	w, err := frontend.NewWitness(assignment(big.NewInt(7)), q)
	if err != nil {
		t.Fatal(err)
	}
	if err = cs.IsSolved(w); err != nil {
		t.Fatal(err)
	}
	alias := new(big.Int).Add(q, big.NewInt(7))
	w, err = frontend.NewWitness(assignment(alias), q)
	if err != nil {
		t.Fatal(err)
	}
	var nBits solver.Hint
	for _, h := range bits.GetHints() {
		if strings.HasSuffix(solver.GetHintName(h), ".nBits") {
			nBits = h
		}
	}
	if nBits == nil {
		t.Fatal("missing binary decomposition hint")
	}
	called := false
	attack := func(field *big.Int, in, out []*big.Int) error {
		if len(in) == 1 && len(out) == q.BitLen() && in[0].Cmp(big.NewInt(7)) == 0 {
			called = true
			for i := range out {
				out[i].SetUint64(uint64(alias.Bit(i)))
			}
			return nil
		}
		return nBits(field, in, out)
	}
	err = cs.IsSolved(w, solver.OverrideHint(solver.GetHintID(nBits), attack))
	if !called {
		t.Fatal("alias hint did not execute")
	}
	hintattack.RequireConstraintRejection(t, err)
}
