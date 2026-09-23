package registry

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"zolana/prover/prover-test/spp/spptest"
)

func TestZeroNullifierPkIsThePoseidonOfZero(t *testing.T) {
	if got := spptest.MustNullifierPk(t, big.NewInt(0)); got.Cmp(ZeroNullifierPk) != 0 {
		t.Fatalf("Poseidon(0) is %x", got)
	}
}

type escrowCircuit struct {
	Escrow      frontend.Variable
	Root        frontend.Variable
	OwnerPkHash frontend.Variable
	NullifierPk frontend.Variable
	Key         KeyOpening
}

func (c *escrowCircuit) Define(api frontend.API) error {
	AssertMode(api, c.Escrow, c.Root)
	c.Key.AssertEscrowed(api, c.Escrow, c.Root, c.OwnerPkHash, c.NullifierPk)
	return nil
}

// Host leaves hash as head map leaves, the shape register_key inserts.
func TestEscrowOpensTheRegisteredLeaf(t *testing.T) {
	keys := spptest.NewKeyRegistry(t, Height)
	owner, nullifierPk := big.NewInt(0x0a), big.NewInt(0x0b)
	registered := keys.Register(t, owner, nullifierPk, big.NewInt(0x0c))
	keys.Register(t, big.NewInt(0x0d), nullifierPk, big.NewInt(0x0e))
	assignment := func(escrow int, root, owner, nullifierPk *big.Int) *escrowCircuit {
		c := &escrowCircuit{Escrow: escrow, Root: root, OwnerPkHash: owner, NullifierPk: nullifierPk,
			Key: KeyOpening{Next: registered.Next, CtHash: registered.CtHash, Index: registered.Index}}
		for i, node := range keys.Path(registered.Index) {
			c.Key.Path[i] = new(big.Int).Set(&node)
		}
		return c
	}
	tests := []struct {
		name   string
		c      *escrowCircuit
		passes bool
	}{
		{"registered key", assignment(1, keys.Root(), owner, nullifierPk), true},
		{"zero key", assignment(1, keys.Root(), owner, ZeroNullifierPk), true},
		{"escrow off", assignment(0, big.NewInt(0), owner, big.NewInt(0x0f)), true},
		{"another key", assignment(1, keys.Root(), owner, big.NewInt(0x0f)), false},
		{"another owner", assignment(1, keys.Root(), big.NewInt(0x0d), nullifierPk), false},
		{"root with escrow off", assignment(0, keys.Root(), owner, nullifierPk), false},
		{"escrow flag not boolean", assignment(2, keys.Root(), owner, nullifierPk), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := test.IsSolved(&escrowCircuit{}, tt.c, ecc.BN254.ScalarField())
			if (err == nil) != tt.passes {
				t.Fatalf("passes=%v, solve=%v", tt.passes, err)
			}
		})
	}
}
