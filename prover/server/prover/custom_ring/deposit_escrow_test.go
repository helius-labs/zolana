package custom_ring

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"zolana/prover/custom_rings/circuits/deposit"
	"zolana/prover/custom_rings/circuits/registry"
	"zolana/prover/prover-test/spp/spptest"
)

func zeroedKeyPath() [registry.Height]*big.Int {
	var path [registry.Height]*big.Int
	for i := range path {
		path[i] = big.NewInt(0)
	}
	return path
}

// Registers every occupied slot's key and turns escrow on.
func escrowDeposits(t *testing.T, p *DepositParameters) *spptest.KeyRegistry {
	t.Helper()
	keys := spptest.NewKeyRegistry(t, registry.Height)
	registered := make([]spptest.RegisteredKey, p.Count)
	for i := range registered {
		registered[i] = keys.Register(t, p.OwnerPkHashes[i], p.NullifierPks[i], big.NewInt(int64(0xc0+i)))
	}
	for i, key := range registered {
		p.Keys[i] = registryKey(keys, key)
	}
	p.KeyEscrow = KeyEscrow{Enabled: true, Root: keys.Root()}
	return keys
}

func registryKey(keys *spptest.KeyRegistry, key spptest.RegisteredKey) *RegistryKey {
	opening := &RegistryKey{Next: key.Next, CtHash: key.CtHash, Index: key.Index}
	for i, node := range keys.Path(key.Index) {
		opening.Path[i] = new(big.Int).Set(&node)
	}
	return opening
}

func TestDepositKeysMustBeEscrowed(t *testing.T) {
	tests := []struct {
		name   string
		change func(*testing.T, *DepositParameters)
		passes bool
	}{
		{"registered keys", func(t *testing.T, p *DepositParameters) { escrowDeposits(t, p) }, true},
		{"zero key without a registration", func(t *testing.T, p *DepositParameters) {
			escrowDeposits(t, p)
			p.NullifierPks[1], p.Keys[1] = registry.ZeroNullifierPk, nil
		}, true},
		{"unregistered keys with escrow off", func(*testing.T, *DepositParameters) {}, true},
		{"unregistered key", func(t *testing.T, p *DepositParameters) {
			escrowDeposits(t, p)
			p.Keys[1] = nil
		}, false},
		{"registry root with escrow off", func(t *testing.T, p *DepositParameters) {
			escrowDeposits(t, p)
			p.KeyEscrow.Enabled = false
		}, false},
		{"another slot's leaf", func(t *testing.T, p *DepositParameters) {
			escrowDeposits(t, p)
			p.Keys[1] = p.Keys[0]
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vector, _ := depositFixture(t, 2)
			p := vector.Params
			tt.change(t, p)
			encryptDepositVector(t, p)
			assignment, err := p.CreateWitness()
			if err != nil {
				t.Fatal(err)
			}
			err = test.IsSolved(&deposit.CustomRingDepositCircuit{}, assignment, ecc.BN254.ScalarField())
			if (err == nil) != tt.passes {
				t.Fatalf("passes=%v, solve=%v", tt.passes, err)
			}
		})
	}
}
