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

type p256OwnerIdentityCircuit struct {
	X        [32]frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *p256OwnerIdentityCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(P256OwnerIdentity(api, c.X), c.Expected)
	return nil
}

// solanaOwnerTag mirrors the program-side tag; no circuit defines it because
// Solana identities never get hashed in-circuit.
const solanaOwnerTag = 0x53

func TestP256OwnerIdentityMatchesTaggedHashBytes(t *testing.T) {
	x := [32]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	}
	expected := hostHashBytes(t, append([]byte{P256OwnerTag}, x[:]...))

	untagged := hostHashBytes(t, x[:])
	if expected.Cmp(untagged) == 0 {
		t.Fatal("P256 identity equals the untagged hash_bytes_32 of x")
	}
	solanaTagged := hostHashBytes(t, append([]byte{solanaOwnerTag}, x[:]...))
	if expected.Cmp(solanaTagged) == 0 {
		t.Fatal("P256 identity equals the Solana-tagged identity of the same bytes")
	}
	reversed := slices.Clone(x[:])
	slices.Reverse(reversed)
	if expected.Cmp(hostHashBytes(t, append([]byte{P256OwnerTag}, reversed...))) == 0 {
		t.Fatal("test vector does not distinguish big-endian from reversed byte order")
	}

	assignment := p256OwnerIdentityCircuit{Expected: expected}
	for i, b := range x {
		assignment.X[i] = b
	}
	if err := test.IsSolved(
		&p256OwnerIdentityCircuit{},
		&assignment,
		ecc.BN254.ScalarField(),
	); err != nil {
		t.Fatalf("solve P256OwnerIdentity circuit: %v", err)
	}

	assignment.Expected = untagged
	if err := test.IsSolved(
		&p256OwnerIdentityCircuit{},
		&assignment,
		ecc.BN254.ScalarField(),
	); err == nil {
		t.Fatal("circuit accepted the untagged hash_bytes_32 as the P256 identity")
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
