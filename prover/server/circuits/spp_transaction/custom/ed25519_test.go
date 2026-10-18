package customring

import (
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	checked "github.com/helius-labs/zolana/prover/server/circuits/gadget/v2"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// ed25519DigestCircuit hashes the reassembled bytes untagged, the way the
// Ed25519 message digest enters the public input hash.
type ed25519DigestCircuit struct {
	Bits     [256]frontend.Variable
	Expected frontend.Variable
}

func (c *ed25519DigestCircuit) Define(api frontend.API) error {
	bytes := checked.BitsToBytesBE(api, c.Bits[:])
	api.AssertIsEqual(gadget.HashBytes(api, bytes), c.Expected)
	return nil
}

func TestEd25519DigestMatchesProtocolByteOrder(t *testing.T) {
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

	// The circuit decomposes the two digest limbs into little-endian bits;
	// the helper must restore the original big-endian digest bytes.
	value := new(big.Int).SetBytes(digest[:])
	assignment := ed25519DigestCircuit{Expected: expected}
	for i := range assignment.Bits {
		assignment.Bits[i] = value.Bit(i)
	}
	if err := test.IsSolved(
		&ed25519DigestCircuit{},
		&assignment,
		ecc.BN254.ScalarField(),
	); err != nil {
		t.Fatalf("solve Ed25519 digest circuit: %v", err)
	}
}
