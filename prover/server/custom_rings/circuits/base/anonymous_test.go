package base_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	base "github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// The host independently hashes the hidden owner, note commitments and
// disclosed bytes. Mutations must break the same proof used by the program.
func TestAnonymousDisclosure(t *testing.T) {
	keys := ringaudit.DefaultKeys(t)
	statement := keys.AnonymousStatement(t)
	cs := testConstraintSystem(t)
	assignment := keys.Circuit(t, statement)
	solve(t, cs, assignment)

	for _, encoding := range []string{"legacy tag", "coordinate alias"} {
		t.Run(encoding, func(t *testing.T) {
			bad := statement
			if encoding == "legacy tag" {
				bad.Audit.RecipientViewingKeys[0][0] = 3
			} else {
				for i := 1; i < 33; i++ {
					bad.Audit.RecipientViewingKeys[0][i] = 255
				}
				bad.Audit.RecipientViewingKeys[0][1], bad.Audit.RecipientViewingKeys[0][32] = 237, 127
			}
			reject(t, cs, keys.Circuit(t, bad))
		})
	}

	for _, tc := range []struct {
		name string
		edit func(*base.CustomRingBaseCircuit)
	}{
		{"sender changed", func(c *base.CustomRingBaseCircuit) { c.Sender[1] = 3 }},
		{"sender tag changed", func(c *base.CustomRingBaseCircuit) { c.Sender[0] = 0x50 }},
		{"input amount changed", func(c *base.CustomRingBaseCircuit) { c.Inputs[0].Amount = 101 }},
		{"recipient changed", func(c *base.CustomRingBaseCircuit) { c.Recipients[0][1] = 3 }},
		{"recipient tag changed", func(c *base.CustomRingBaseCircuit) { c.Recipients[0][0] = 0x50 }},
		{"recipient viewing key changed", func(c *base.CustomRingBaseCircuit) { c.RecipientViewingKeys[0][1] = 9 }},
		{"address input", func(c *base.CustomRingBaseCircuit) { c.Inputs[0].Domain = protocol.AddressDomain }},
		{"output count changed", func(c *base.CustomRingBaseCircuit) { c.NOut = 2 }},
		{"input count changed", func(c *base.CustomRingBaseCircuit) { c.NIn = 2 }},
		{"no input", func(c *base.CustomRingBaseCircuit) { c.NIn = 0 }},
		{"blinding changed", func(c *base.CustomRingBaseCircuit) { c.PrivateTxBlinding = 1 }},
		{"legacy flag", func(c *base.CustomRingBaseCircuit) { c.Anonymous = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := *assignment
			tc.edit(&bad)
			reject(t, cs, &bad)
		})
	}
}

func TestWideAnonymousDisclosureBindsLastInput(t *testing.T) {
	keys := ringaudit.DefaultKeys(t)
	statement := keys.AnonymousStatement(t)
	first := statement.Inputs[0]
	statement.NIn = 12
	statement.Inputs = make([]base.AuditUtxoWires, 12)
	for i := range statement.Inputs {
		statement.Inputs[i] = first
		statement.Inputs[i].Blinding = big.NewInt(int64(100 + i))
	}
	statement.Rebind(t)
	valid := base.CustomRingWideBaseCircuit{
		PublicInputHash: spptest.MustHashChain(t, keys.ChainElementsFor(t, statement)),
		Audit:           statement.Audit, NOut: statement.Count, Outputs: statement.Outputs,
		NIn: statement.NIn, AnonymousOutputs: statement.Notes,
		PrivateTxBlinding: statement.PrivateTxBlinding,
	}
	copy(valid.Inputs[:], statement.Inputs)
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder,
		&base.CustomRingWideBaseCircuit{}, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*base.CustomRingWideBaseCircuit)
	}{
		{"valid", nil},
		{"last input amount", func(c *base.CustomRingWideBaseCircuit) { c.Inputs[11].Amount = 101 }},
		{"last input owner", func(c *base.CustomRingWideBaseCircuit) { c.Inputs[11].OwnerPkHash = 1 }},
		{"missing input", func(c *base.CustomRingWideBaseCircuit) { c.NIn = 11 }},
		{"wrong mode", func(c *base.CustomRingWideBaseCircuit) { c.Anonymous = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := valid
			if tc.edit != nil {
				tc.edit(&w)
			}
			witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			err = cs.IsSolved(witness)
			if (err == nil) != (tc.edit == nil) {
				t.Fatalf("unexpected solve result: %v", err)
			}
		})
	}
}

// Every disclosed input must be the sender's, and a ring output the Ed25519 rail's.
func TestAnonymousDisclosureRejectsForeignOwners(t *testing.T) {
	keys := ringaudit.DefaultKeys(t)
	cs := testConstraintSystem(t)
	for name, edit := range map[string]func(*ringaudit.Statement){
		"input of another owner": func(s *ringaudit.Statement) {
			_, other := ringaudit.Identity(t, 0xc3)
			s.Inputs[0].OwnerPkHash = other
		},
		"ring output to an invalid owner tag": func(s *ringaudit.Statement) {
			s.Audit.Recipients[0][0] = 0x50
			hash, err := protocol.HashBytes(append([]byte{0x50}, make32(0xb2)...))
			if err != nil {
				t.Fatal(err)
			}
			s.Notes[0].OwnerPkHash = hash
		},
		"only a dummy input": func(s *ringaudit.Statement) {
			s.Inputs[0].Domain = big.NewInt(protocol.DummyDomain)
		},
	} {
		t.Run(name, func(t *testing.T) {
			statement := keys.AnonymousStatement(t)
			edit(&statement)
			statement.Rebind(t)
			reject(t, cs, keys.Circuit(t, statement))
		})
	}
	// A note that leaves the ring may go to any owner.
	statement := keys.AnonymousStatement(t)
	statement.Audit.Recipients[0][0] = 0x50
	hash, err := protocol.HashBytes(append([]byte{0x50}, make32(0xb2)...))
	if err != nil {
		t.Fatal(err)
	}
	statement.Notes[0].OwnerPkHash, statement.Notes[0].RingProgramID = hash, big.NewInt(0)
	statement.Rebind(t)
	solve(t, cs, keys.Circuit(t, statement))
}

func make32(seed byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = seed
	}
	return out
}

func reject(t *testing.T, cs constraint.ConstraintSystem, assignment *base.CustomRingBaseCircuit) {
	t.Helper()
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if cs.IsSolved(w) == nil {
		t.Fatal("tampered anonymous witness solved")
	}
}
