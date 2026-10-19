package gadget

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
)

type committedBytesCircuit struct {
	Bytes    [32]frontend.Variable
	Expected frontend.Variable `gnark:",public"`
	Identity bool              `gnark:"-"`
}

func (c *committedBytesCircuit) Define(api frontend.API) error {
	var actual frontend.Variable
	if c.Identity {
		actual = SolanaOwnerIdentity(api, c.Bytes)
	} else {
		actual = HashBytes(api, c.Bytes[:])
	}
	api.AssertIsEqual(actual, c.Expected)
	return nil
}

// Carrying 256 into the preceding byte preserves unchecked packed integers,
// including their hashes. Each public byte boundary must reject that alias.
func TestByteCommitmentsRejectPackingAliases(t *testing.T) {
	for _, identity := range []bool{false, true} {
		name := "hash"
		if identity {
			name = "owner identity"
		}
		t.Run(name, func(t *testing.T) {
			key := [32]byte{1, 0, 2}
			key[31] = 91
			expected, err := protocol.HashBytes(key[:])
			if identity {
				expected, err = protocol.SolanaPkField(key)
			}
			if err != nil {
				t.Fatal(err)
			}
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &committedBytesCircuit{Identity: identity})
			if err != nil {
				t.Fatal(err)
			}
			assignment := committedBytesCircuit{Expected: expected, Identity: identity}
			for i, b := range key {
				assignment.Bytes[i] = b
			}
			check := func(a *committedBytesCircuit, valid bool) {
				t.Helper()
				witness, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				err = cs.IsSolved(witness)
				if valid {
					if err != nil {
						t.Fatal(err)
					}
				} else {
					hintattack.RequireConstraintRejection(t, err)
				}
			}
			check(&assignment, true)
			alias := assignment
			alias.Bytes[0], alias.Bytes[1] = 0, 256
			check(&alias, false)
			changed := assignment
			changed.Bytes[31] = 92
			check(&changed, false)
		})
	}
}
