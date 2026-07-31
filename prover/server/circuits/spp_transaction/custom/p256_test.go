package customzone

import (
	"math/big"
	"slices"
	"testing"

	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type hashBytes32BitsCircuit struct {
	Bits     [256]frontend.Variable
	Expected frontend.Variable
}

func (c *hashBytes32BitsCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(hashBytes32Bits(api, c.Bits[:]), c.Expected)
	return nil
}

func TestHashBytes32BitsMatchesProtocolByteOrder(t *testing.T) {
	digest := [32]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	}
	expected, err := protocol.HashBytes(digest[:])
	if err != nil {
		t.Fatalf("hash digest bytes: %v", err)
	}

	reversed := slices.Clone(digest[:])
	slices.Reverse(reversed)
	reversedHash, err := protocol.HashBytes(reversed)
	if err != nil {
		t.Fatalf("hash reversed digest bytes: %v", err)
	}
	if expected.Cmp(reversedHash) == 0 {
		t.Fatal("test vector does not distinguish big-endian from reversed byte order")
	}

	value := new(big.Int).SetBytes(digest[:])
	assignment := hashBytes32BitsCircuit{Expected: expected}
	for i := range assignment.Bits {
		assignment.Bits[i] = value.Bit(i)
	}

	if err := test.IsSolved(
		&hashBytes32BitsCircuit{},
		&assignment,
		ecc.BN254.ScalarField(),
	); err != nil {
		t.Fatalf("solve hashBytes32Bits circuit: %v", err)
	}
}
