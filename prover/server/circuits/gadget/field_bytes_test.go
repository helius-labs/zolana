package gadget

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
)

type fieldBytesCircuit struct {
	Value frontend.Variable
	Bytes [32]frontend.Variable `gnark:",public"`
}

func (c *fieldBytesCircuit) Define(api frontend.API) error {
	for i, b := range FieldToBytesBEWith(api, rangecheck.New(api), c.Value) {
		api.AssertIsEqual(b, c.Bytes[i])
	}
	return nil
}

func TestFieldToBytesBEWithBoundariesAndForgedHints(t *testing.T) {
	q := ecc.BN254.ScalarField()
	cs, err := frontend.Compile(q, r1cs.NewBuilder, &fieldBytesCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	encode := func(n *big.Int) *fieldBytesCircuit {
		w := &fieldBytesCircuit{Value: new(big.Int).Mod(new(big.Int).Set(n), q)}
		var bytes [32]byte
		n.FillBytes(bytes[:])
		for i, b := range bytes {
			w.Bytes[i] = b
		}
		return w
	}
	solve := func(w *fieldBytesCircuit, options ...solver.Option) error {
		witness, err := frontend.NewWitness(w, q)
		if err != nil {
			t.Fatal(err)
		}
		return cs.IsSolved(witness, options...)
	}
	boundary := new(big.Int).Lsh(big.NewInt(1), 128)
	for _, value := range []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(255), big.NewInt(256),
		new(big.Int).Sub(boundary, big.NewInt(1)), boundary,
		new(big.Int).Add(boundary, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1))} {
		if err := solve(encode(value)); err != nil {
			t.Fatalf("boundary %s: %v", value, err)
		}
	}
	for _, multiple := range []int64{1, 2, 5} {
		alias := new(big.Int).Add(new(big.Int).Mul(q, big.NewInt(multiple)), big.NewInt(7))
		w := encode(alias)
		called := false
		attack := func(field *big.Int, in, out []*big.Int) error {
			called = true
			if err := fieldBytesHint(field, in, out); err != nil {
				return err
			}
			var bytes [32]byte
			alias.FillBytes(bytes[:])
			for i, b := range bytes {
				out[i].SetUint64(uint64(b))
			}
			return nil
		}
		err := solve(w, solver.OverrideHint(solver.GetHintID(fieldBytesHint), attack))
		if !called {
			t.Fatal("alias attack did not run")
		}
		hintattack.RequireConstraintRejection(t, err)
	}
	for _, attackName := range []string{"byte carry", "gap carry", "nonboolean carry"} {
		t.Run(attackName, func(t *testing.T) {
			w := encode(big.NewInt(7))
			if attackName == "byte carry" {
				w.Bytes[30], w.Bytes[31] = 1, -249
			}
			attack := func(field *big.Int, in, out []*big.Int) error {
				if err := fieldBytesHint(field, in, out); err != nil {
					return err
				}
				switch attackName {
				case "byte carry":
					out[30].SetInt64(1)
					out[31].SetInt64(-249)
				case "gap carry":
					out[32].Add(out[32], boundary)
					out[33].Sub(out[33], big.NewInt(1))
					out[34].Add(out[34], big.NewInt(1))
				case "nonboolean carry":
					out[34].SetInt64(2)
				}
				return nil
			}
			hintattack.RequireConstraintRejection(t, solve(w, solver.OverrideHint(solver.GetHintID(fieldBytesHint), attack)))
		})
	}
}
