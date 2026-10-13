package gadget

import (
	"math/big"
	"slices"
	"testing"

	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type solanaOwnerIdentityCircuit struct {
	X        [32]frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *solanaOwnerIdentityCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(SolanaOwnerIdentity(api, c.X), c.Expected)
	return nil
}

// TestSolanaOwnerTagMirrorsHost pins the circuit tag to the host constant; the
// circuits package cannot import the host, so the two are kept equal by test.
func TestSolanaOwnerTagMirrorsHost(t *testing.T) {
	if SolanaOwnerTag != protocol.SolanaOwnerTag {
		t.Fatalf("gadget.SolanaOwnerTag = 0x%02x, protocol.SolanaOwnerTag = 0x%02x", SolanaOwnerTag, protocol.SolanaOwnerTag)
	}
}

func TestSolanaOwnerIdentityMatchesHost(t *testing.T) {
	x := [32]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	}
	expected, err := protocol.SolanaPkField(x)
	if err != nil {
		t.Fatalf("host solana identity: %v", err)
	}

	untagged := hostHashBytes(t, x[:])
	if expected.Cmp(untagged) == 0 {
		t.Fatal("Solana identity equals the untagged hash_bytes_32 of the key")
	}
	reversed := slices.Clone(x[:])
	slices.Reverse(reversed)
	if expected.Cmp(hostHashBytes(t, append([]byte{SolanaOwnerTag}, reversed...))) == 0 {
		t.Fatal("test vector does not distinguish big-endian from reversed byte order")
	}

	assignment := solanaOwnerIdentityCircuit{Expected: expected}
	for i, b := range x {
		assignment.X[i] = b
	}
	if err := test.IsSolved(
		&solanaOwnerIdentityCircuit{},
		&assignment,
		ecc.BN254.ScalarField(),
	); err != nil {
		t.Fatalf("solve SolanaOwnerIdentity circuit: %v", err)
	}

	assignment.Expected = untagged
	if err := test.IsSolved(
		&solanaOwnerIdentityCircuit{},
		&assignment,
		ecc.BN254.ScalarField(),
	); err == nil {
		t.Fatal("circuit accepted the untagged hash_bytes_32 as the Solana identity")
	}
}

func hostHashBytes(t testing.TB, bytes []byte) *big.Int {
	t.Helper()
	hash, err := protocol.HashBytes(bytes)
	if err != nil {
		t.Fatalf("host hash_bytes over %d bytes: %v", len(bytes), err)
	}
	return hash
}
