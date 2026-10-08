package aes

import (
	"math/rand"
	"testing"
	"testing/quick"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/prover/prover-test/hintattack"
)

type spreadBytePropertyCircuit struct {
	Bytes    [256]frontend.Variable
	Expected [256]frontend.Variable
}

func (c *spreadBytePropertyCircuit) Define(api frontend.API) error {
	tables := sharedSpreadTables(api)
	// Every populated table needs a query, including the unused AES S-box.
	tables.substitute(sboxRegion, c.Bytes[0])
	for i, value := range c.Bytes {
		spread := tables.spreadByte(value)
		api.AssertIsEqual(spread, c.Expected[i])
		api.AssertIsEqual(tables.decodeWordSum(spread, 1)[0], value)
	}
	return nil
}

func solveSpreadCircuit(t *testing.T, cs constraint.ConstraintSystem, assignment frontend.Circuit) error {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return cs.IsSolved(witness)
}

func TestSpreadByteExhaustive(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &spreadBytePropertyCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	var assignment spreadBytePropertyCircuit
	var expected [256]int
	for value := range assignment.Bytes {
		// Read the binary digits from most to least significant in base 6.
		// This reference uses neither spreadValue nor the production constants.
		for bit := 7; bit >= 0; bit-- {
			expected[value] = 6*expected[value] + ((value >> bit) & 1)
		}
		assignment.Bytes[value] = value
		assignment.Expected[value] = expected[value]
	}
	if err := solveSpreadCircuit(t, cs, &assignment); err != nil {
		t.Fatal(err)
	}
	for _, position := range []int{0, 1, 128, 255} {
		tampered := assignment
		tampered.Expected[position] = expected[position] + 1
		hintattack.RequireConstraintRejection(t, solveSpreadCircuit(t, cs, &tampered))
	}
}

type spreadXORPropertyCircuit struct {
	Bytes [5]frontend.Variable
	XOR   [5]frontend.Variable
}

func (c *spreadXORPropertyCircuit) Define(api frontend.API) error {
	tables := sharedSpreadTables(api)
	// Every populated table needs a query, including the unused AES S-box.
	tables.substitute(sboxRegion, c.Bytes[0])
	var sum frontend.Variable = 0
	for i, value := range c.Bytes {
		sum = api.Add(sum, tables.spreadByte(value))
		api.AssertIsEqual(tables.decodeWordSum(sum, 1)[0], c.XOR[i])
	}
	return nil
}

func spreadXORAssignment(bytes [5]byte) *spreadXORPropertyCircuit {
	assignment := new(spreadXORPropertyCircuit)
	var xor byte
	for i, value := range bytes {
		xor ^= value
		assignment.Bytes[i] = value
		assignment.XOR[i] = xor
	}
	return assignment
}

func TestSpreadByteSumParityMatchesXOR(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &spreadXORPropertyCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	for _, bytes := range [][5]byte{
		{},
		{0xff, 0xff, 0xff, 0xff, 0xff}, // Reach every lane's maximum sum of 5.
		{0xaa, 0x55, 0xaa, 0x55, 0xff},
		{0x80, 0x80, 0x80, 0x80, 0x80},
		{0x01, 0x01, 0x01, 0x01, 0x01},
	} {
		if err := solveSpreadCircuit(t, cs, spreadXORAssignment(bytes)); err != nil {
			t.Fatalf("bytes %x: %v", bytes, err)
		}
	}

	// Each generated input checks all prefix lengths, from one to five bytes.
	property := func(bytes [5]byte) bool {
		if err := solveSpreadCircuit(t, cs, spreadXORAssignment(bytes)); err != nil {
			t.Logf("bytes %x: %v", bytes, err)
			return false
		}
		return true
	}
	if err := quick.Check(property, &quick.Config{
		MaxCount: 100,
		Rand:     rand.New(rand.NewSource(1)),
	}); err != nil {
		t.Fatal(err)
	}

	for position := range 5 {
		tampered := spreadXORAssignment([5]byte{0xff, 0xff, 0xff, 0xff, 0xff})
		tampered.XOR[position] = 1 // Honest prefixes are 0 or 255.
		hintattack.RequireConstraintRejection(t, solveSpreadCircuit(t, cs, tampered))
	}
}
