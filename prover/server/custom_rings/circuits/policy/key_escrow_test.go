package policy

import (
	"math/big"
	"testing"

	"zolana/prover/custom_rings/circuits/registry"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
)

func TestRegistryHeightIsTheHeadMapHeight(t *testing.T) {
	if registry.Height != HeadMapHeight {
		t.Fatalf("registry height %d, head map height %d", registry.Height, HeadMapHeight)
	}
}

// Registers every UTXO output's key and turns escrow on.
func (s *statement) escrowOutputs(t *testing.T) *spptest.KeyRegistry {
	t.Helper()
	keys := spptest.NewKeyRegistry(t, registry.Height)
	registered := make([]*spptest.RegisteredKey, len(s.outputs))
	for i, output := range s.outputs {
		if spptest.AsBigInt(output.Domain).Int64() != protocol.UtxoDomain {
			continue
		}
		key := keys.Register(t, spptest.AsBigInt(output.OwnerPkHash), spptest.AsBigInt(output.NullifierPk), big.NewInt(int64(0xc0+i)))
		registered[i] = &key
	}
	s.outputKeys = make([]*registry.KeyOpening, len(s.outputs))
	for i, key := range registered {
		if key != nil {
			s.outputKeys[i] = keyOpening(keys, *key)
		}
	}
	s.keyEscrow, s.keyRegistryRoot = true, keys.Root()
	return keys
}

func keyOpening(keys *spptest.KeyRegistry, key spptest.RegisteredKey) *registry.KeyOpening {
	opening := &registry.KeyOpening{Next: key.Next, CtHash: key.CtHash, Index: key.Index}
	for i, node := range keys.Path(key.Index) {
		opening.Path[i] = new(big.Int).Set(&node)
	}
	return opening
}

func TestOutputKeysMustBeEscrowed(t *testing.T) {
	tests := []struct {
		name   string
		change func(*testing.T, *statement)
		passes bool
	}{
		{"registered key beside a keyless dummy output", func(t *testing.T, s *statement) { s.escrowOutputs(t) }, true},
		{"zero key without a registration", func(t *testing.T, s *statement) {
			s.outputs[0].NullifierPk = registry.ZeroNullifierPk
			s.keyEscrow, s.keyRegistryRoot = true, spptest.NewKeyRegistry(t, registry.Height).Root()
		}, true},
		{"unregistered key with escrow off", func(*testing.T, *statement) {}, true},
		{"unregistered key", func(t *testing.T, s *statement) {
			s.escrowOutputs(t)
			s.outputKeys[0] = nil
		}, false},
		{"registry root with escrow off", func(t *testing.T, s *statement) {
			s.escrowOutputs(t)
			s.keyEscrow = false
		}, false},
		{"another owner's leaf", func(t *testing.T, s *statement) {
			keys := s.escrowOutputs(t)
			other := keys.Register(t, pkField(t, fill(0x5e)), spptest.AsBigInt(s.outputs[0].NullifierPk), big.NewInt(0xc0))
			s.keyRegistryRoot = keys.Root()
			s.outputKeys[0] = keyOpening(keys, other)
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := defaultFixture()
			s := newStatement(t, f)
			tt.change(t, s)
			c := s.assignment(t, f.listFacts)
			if tt.passes {
				solve(t, testConstraintSystem(t), c)
			} else {
				rejectAssignment(t, c)
			}
		})
	}
}
