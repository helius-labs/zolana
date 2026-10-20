package gadget

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

type lowBytesCircuit struct {
	Value frontend.Variable
	Bytes [16]frontend.Variable `gnark:",public"`
}

func (c *lowBytesCircuit) Define(api frontend.API) error {
	for i, b := range FieldLowBytesBE(api, BitChecker{api}, c.Value, len(c.Bytes)) {
		api.AssertIsEqual(b, c.Bytes[i])
	}
	return nil
}

func lowBytesWitness(value *big.Int) *lowBytesCircuit {
	w := &lowBytesCircuit{Value: value}
	for i := range w.Bytes {
		w.Bytes[i] = new(big.Int).And(new(big.Int).Rsh(value, uint(8*(15-i))), big.NewInt(0xff))
	}
	return w
}

// The alias value+q stays below 2^254, so only the comparison with q rejects it.
func TestFieldLowBytesBERejectsFieldAlias(t *testing.T) {
	q := ecc.BN254.ScalarField()
	cs, err := frontend.Compile(q, r1cs.NewBuilder, &lowBytesCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	qHigh := new(big.Int).Rsh(q, 128)
	atBound := new(big.Int).Sub(q, big.NewInt(1))
	belowBound := new(big.Int).Sub(new(big.Int).Lsh(qHigh, 128), big.NewInt(1))
	for _, v := range []*big.Int{big.NewInt(0), big.NewInt(5), belowBound, atBound} {
		w, err := frontend.NewWitness(lowBytesWitness(v), q)
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(w); err != nil {
			t.Fatalf("canonical %s rejected: %v", v, err)
		}
	}
	for _, v := range []*big.Int{big.NewInt(5), new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 254), q), big.NewInt(1))} {
		alias := new(big.Int).Add(v, q)
		if alias.BitLen() > 254 {
			t.Fatalf("alias %s exceeds 254 bits", alias)
		}
		forge := func(_ *big.Int, _ []*big.Int, outputs []*big.Int) error {
			rest := new(big.Int).Set(alias)
			for i := len(outputs) - 1; i >= 1; i-- {
				outputs[i].And(rest, big.NewInt(0xff))
				rest.Rsh(rest, 8)
			}
			outputs[0].Set(rest)
			return nil
		}
		forged := lowBytesWitness(alias)
		forged.Value = v
		w, err := frontend.NewWitness(forged, q)
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(w, solver.OverrideHint(solver.GetHintID(lowBytesHint), forge)); err == nil {
			t.Fatalf("alias of %s accepted", v)
		}
	}
}
