package base_test

import (
	"math/big"
	"slices"
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

	for _, encoding := range []string{"wrong tag", "coordinate alias"} {
		t.Run(encoding, func(t *testing.T) {
			bad := statement
			if encoding == "wrong tag" {
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
		PublicInputHash: spptest.MustHashChain(t, keys.BaseChainElementsFor(t, statement)),
		Audit:           statement.Audit, NOut: statement.Count, Outputs: statement.Outputs,
		NIn: statement.NIn, AnonymousOutputs: statement.Notes,
		PrivateTxBlinding: statement.PrivateTxBlinding, Delivery: statement.DeliveryWires(),
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

// Every disclosed input must be the sender's, and every disclosed output owner must carry the Solana owner tag.
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
		"exit to an invalid owner tag": func(s *ringaudit.Statement) {
			s.Audit.Recipients[0][0] = 0x50
			hash, err := protocol.HashBytes(append([]byte{0x50}, make32(0xb2)...))
			if err != nil {
				t.Fatal(err)
			}
			s.Notes[0].OwnerPkHash, s.Notes[0].RingProgramID = hash, big.NewInt(0)
		},
	} {
		t.Run(name, func(t *testing.T) {
			statement := keys.AnonymousStatement(t)
			edit(&statement)
			statement.Rebind(t)
			reject(t, cs, keys.Circuit(t, statement))
		})
	}
}

// exitStatement spends one note into a ring note, an exit to the default ring and a padding slot.
func exitStatement(t *testing.T) (ringaudit.Keys, ringaudit.Statement) {
	t.Helper()
	keys := ringaudit.DefaultKeys(t)
	s := keys.AnonymousStatement(t)
	identity, owner := ringaudit.Identity(t, 0xe5)
	exit := s.Notes[0]
	exit.OwnerPkHash, exit.NullifierPk = owner, spptest.MustNullifierPk(t, big.NewInt(23))
	exit.Amount, exit.Blinding, exit.RingProgramID = big.NewInt(40), big.NewInt(63), big.NewInt(0)
	s.Notes[1] = exit
	for i, b := range identity {
		s.Audit.Recipients[1][i] = int(b)
	}
	s.Notes[2].Domain = big.NewInt(protocol.DummyDomain)
	s.Count = 3
	keys.Deliver(t, &s)
	return keys, s
}

// An exit discloses its opening where a ring note discloses its viewing key, a padding slot stays zero.
func TestAnonymousExitDisclosesItsOpening(t *testing.T) {
	keys, s := exitStatement(t)
	cs := testConstraintSystem(t)
	solve(t, cs, keys.Circuit(t, s))

	plaintext := ringaudit.AnonymousPlaintext(s)
	slot := func(i int) []byte {
		start := ringaudit.HeaderBytes + s.NIn*ringaudit.InputBytes + i*ringaudit.OutputBytes
		return plaintext[start : start+ringaudit.OutputBytes]
	}
	ring, exit, padding := slot(0), slot(1), slot(2)
	if ring[0] != base.OutputKindRing || ring[66] != 4 || exit[0] != base.OutputKindExit || exit[73] != 40 || exit[137] != 63 {
		t.Fatal("the ring and exit slots do not lead with their kind and layout")
	}
	if !slices.Equal(padding, make([]byte, ringaudit.OutputBytes)) {
		t.Fatal("a padding slot discloses bytes")
	}

	// The proof refuses a disclosure that differs from the exit's opening.
	for name, edit := range map[string]func(*ringaudit.Statement){
		"amount":        func(o *ringaudit.Statement) { o.Notes[1].Amount = big.NewInt(41) },
		"asset":         func(o *ringaudit.Statement) { o.Notes[1].Asset = big.NewInt(7) },
		"blinding":      func(o *ringaudit.Statement) { o.Notes[1].Blinding = big.NewInt(64) },
		"owner":         func(o *ringaudit.Statement) { o.Audit.Recipients[1][2] = 0xe6 },
		"nullifier key": func(o *ringaudit.Statement) { o.Notes[1].NullifierPk = spptest.MustNullifierPk(t, big.NewInt(24)) },
		"ring kind":     func(o *ringaudit.Statement) { o.Notes[1].RingProgramID = o.Notes[0].RingProgramID },
	} {
		t.Run(name, func(t *testing.T) {
			other := s
			edit(&other)
			elements := keys.BaseChainElementsFor(t, s)
			elements[chainDisclosureHash] = keys.BaseChainElementsFor(t, other)[chainDisclosureHash]
			circuit := keys.Circuit(t, s)
			circuit.PublicInputHash = spptest.MustHashChain(t, elements)
			reject(t, cs, circuit)
		})
	}

	// The proof refuses an exit with a data hash the auditor cannot rebuild.
	for name, edit := range map[string]func(*base.AuditUtxoWires){
		"data hash":      func(w *base.AuditUtxoWires) { w.DataHash = big.NewInt(5) },
		"ring data hash": func(w *base.AuditUtxoWires) { w.RingDataHash = big.NewInt(5) },
	} {
		t.Run(name, func(t *testing.T) {
			withData := s
			edit(&withData.Notes[1])
			withData.Rebind(t)
			reject(t, cs, keys.Circuit(t, withData))
		})
	}
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
