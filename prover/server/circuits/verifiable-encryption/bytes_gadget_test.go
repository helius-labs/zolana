package verifiableencryption_test

import (
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/prover-test/hintattack"
	"zolana/prover/prover-test/hosttest"
)

type bytesBigEndianCircuit struct {
	Value frontend.Variable
	Bytes []frontend.Variable `gnark:",public"`
}

func (c *bytesBigEndianCircuit) Define(api frontend.API) error {
	for i, b := range ve.BytesBigEndian(api, c.Value, len(c.Bytes)) {
		api.AssertIsEqual(b, c.Bytes[i])
	}
	return nil
}

type fieldToBytesCircuit struct {
	Value frontend.Variable
	Bytes [32]frontend.Variable `gnark:",public"`
}

func (c *fieldToBytesCircuit) Define(api frontend.API) error {
	for i, b := range ve.FieldToBytesBE(api, c.Value, len(c.Bytes)) {
		api.AssertIsEqual(b, c.Bytes[i])
	}
	return nil
}

func compileGadget(t *testing.T, circuit frontend.Circuit) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func lowBytes(value *big.Int, n int) []*big.Int {
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = new(big.Int)
	}
	if err := ve.LowBytesHint(nil, []*big.Int{value}, out); err != nil {
		panic(err)
	}
	return out
}

func bytesBigEndianAssignment(value *big.Int, bytes []*big.Int) *bytesBigEndianCircuit {
	a := &bytesBigEndianCircuit{Value: value, Bytes: make([]frontend.Variable, len(bytes))}
	for i, b := range bytes {
		a.Bytes[i] = b
	}
	return a
}

func topByteOverflow(bytes []*big.Int) {
	bytes[0].Add(bytes[0], big.NewInt(256))
}

func lowByteBorrow(bytes []*big.Int) {
	n := len(bytes)
	bytes[n-1].Add(bytes[n-1], big.NewInt(256))
	bytes[n-2].Sub(bytes[n-2], big.NewInt(1))
}

func forgedLowBytes(forge func([]*big.Int)) solver.Option {
	return solver.OverrideHint(solver.GetHintID(ve.LowBytesHint), func(mod *big.Int, inputs, outputs []*big.Int) error {
		if err := ve.LowBytesHint(mod, inputs, outputs); err != nil {
			return err
		}
		forge(outputs)
		return nil
	})
}

func TestBytesBigEndianGadgetBoundsTheValue(t *testing.T) {
	for _, n := range []int{8, 31} {
		t.Run(fmt.Sprintf("%d bytes", n), func(t *testing.T) {
			cs := compileGadget(t, &bytesBigEndianCircuit{Bytes: make([]frontend.Variable, n)})
			bound := new(big.Int).Lsh(big.NewInt(1), uint(8*n))
			largest := new(big.Int).Sub(bound, big.NewInt(1))
			above := new(big.Int).Add(bound, big.NewInt(1))

			if err := solveCompiled(t, cs, bytesBigEndianAssignment(largest, lowBytes(largest, n))); err != nil {
				t.Fatalf("2^%d - 1 rejected: %v", 8*n, err)
			}
			for _, row := range []struct {
				name  string
				value *big.Int
			}{
				{"2^8n through its wrapped low bytes", bound},
				{"2^8n plus one through its wrapped low bytes", above},
			} {
				t.Run(row.name, func(t *testing.T) {
					hintattack.RequireConstraintRejection(t, solveCompiled(t, cs, bytesBigEndianAssignment(row.value, lowBytes(row.value, n))))
				})
			}

			for _, prover := range hosttest.RangeCheckProvers(t) {
				t.Run(prover.Name, func(t *testing.T) {
					if err := solveCompiled(t, cs, bytesBigEndianAssignment(largest, lowBytes(largest, n)), prover.Options...); err != nil {
						t.Fatalf("2^%d - 1 rejected: %v", 8*n, err)
					}
					for _, row := range []struct {
						name  string
						value *big.Int
						forge func([]*big.Int)
					}{
						{"2^8n through a top byte of 256", bound, topByteOverflow},
						{"2^8n plus one through a top byte of 256", above, topByteOverflow},
						{"2^8n minus one with the low byte borrowing 256", largest, lowByteBorrow},
					} {
						t.Run(row.name, func(t *testing.T) {
							bytes := lowBytes(row.value, n)
							row.forge(bytes)
							opts := append(slices.Clone(prover.Options), forgedLowBytes(row.forge))
							hintattack.RequireConstraintRejection(t, solveCompiled(t, cs, bytesBigEndianAssignment(row.value, bytes), opts...))
						})
					}
				})
			}
		})
	}
}

func TestBytesBigEndianGadgetRefusesThirtyTwoBytes(t *testing.T) {
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &bytesBigEndianCircuit{Bytes: make([]frontend.Variable, 32)})
	if err == nil {
		t.Fatal("a 32-byte decomposition compiled")
	}
	if !strings.Contains(err.Error(), "bytes big endian: 32 bytes, want 1 to 31") {
		t.Fatalf("compile failed for another reason: %v", err)
	}
}

func TestFieldToBytesGadgetMatchesHost(t *testing.T) {
	cs := compileGadget(t, &fieldToBytesCircuit{})
	r := ecc.BN254.ScalarField()
	for _, row := range []struct {
		name  string
		value *big.Int
	}{
		{"zero", big.NewInt(0)},
		{"one", big.NewInt(1)},
		{"modulus minus one", new(big.Int).Sub(r, big.NewInt(1))},
		{"2^255 mod modulus", new(big.Int).Mod(new(big.Int).Lsh(big.NewInt(1), 255), r)},
	} {
		t.Run(row.name, func(t *testing.T) {
			a := &fieldToBytesCircuit{Value: row.value}
			for i, b := range row.value.FillBytes(make([]byte, 32)) {
				a.Bytes[i] = b
			}
			if err := solveCompiled(t, cs, a); err != nil {
				t.Fatalf("host bytes rejected: %v", err)
			}
		})
	}
}
