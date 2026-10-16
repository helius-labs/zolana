package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

var registerCs constraint.ConstraintSystem

func registerSystem(t *testing.T) constraint.ConstraintSystem {
	t.Helper()
	if registerCs == nil {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &KeyRegisterCircuit{}, frontend.WithCompressThreshold(300))
		if err != nil {
			t.Fatal(err)
		}
		registerCs = cs
	}
	return registerCs
}

// groth16-solana accepts exactly one BSB22 commitment over private wires.
func TestKeyRegisterCommitmentShape(t *testing.T) {
	cs := registerSystem(t)
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok {
		t.Fatalf("unexpected commitments type %T", cs.GetCommitments())
	}
	if len(commitments) != 1 {
		t.Fatalf("expected 1 BSB22 commitment, got %d", len(commitments))
	}
	if got := commitments[0].NbPublicCommitted; got != 0 {
		t.Fatalf("expected 0 public committed wires, got %d", got)
	}
	t.Logf("register_key: %d constraints, 1 commitment over %d private wires",
		cs.GetNbConstraints(), len(commitments[0].PrivateCommitted))
}

// registerKeyAssignment seals a nullifier secret for the member and writes the key into its record.
func registerKeyAssignment(t *testing.T, members *spptest.MemberRegistry, member *big.Int) *KeyRegisterCircuit {
	t.Helper()
	secret := ringaudit.Scalar(0x07)
	secret[0] = 0
	keys := ringaudit.DefaultKeys(t)
	sealed := keys.Seal(t, secret[:], NfKeyEncInfo)
	nullifierPk := spptest.MustNullifierPk(t, new(big.Int).SetBytes(secret[1:]))
	update := members.RegisterKey(t, member, nullifierPk, sealed.CiphertextHash)
	c := &KeyRegisterCircuit{
		RegistryOldRoot: update.OldRoot, RegistryNewRoot: update.NewRoot, Member: member, Lists: update.Lists,
		RecordUpdate: updateWires(update),
	}
	for i := range secret {
		c.NullifierSecret[i] = int(secret[i])
	}
	eph, auditor := keys.EphSk(), keys.AuditorPk()
	for i := range eph {
		c.EphSk[i], c.AuditorPk[i] = int(eph[i]), int(auditor[i])
	}
	c.PublicInputHash = spptest.MustHashChain(t, []*big.Int{
		update.OldRoot, update.NewRoot, member, nullifierPk,
		sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, sealed.CiphertextHash, new(big.Int).SetUint64(update.Index),
	})
	return c
}

func updateWires(w spptest.MemberUpdateWitness) registry.RecordUpdate {
	u := registry.RecordUpdate{Exists: boolVar(w.Exists), Next: w.Next, Index: new(big.Int).SetUint64(w.Index),
		LowMember: big.NewInt(0), LowNext: big.NewInt(0), LowLists: big.NewInt(0), LowEscrow: big.NewInt(0), LowIndex: big.NewInt(0)}
	for i := range u.Path {
		u.Path[i], u.LowPath[i] = big.NewInt(0), big.NewInt(0)
	}
	for i := range w.Path {
		u.Path[i] = new(big.Int).Set(&w.Path[i])
	}
	if w.Exists {
		return u
	}
	u.LowMember, u.LowNext, u.LowLists, u.LowEscrow = w.Low.Member, w.Low.Next, w.Low.Lists, w.Low.EscrowKey
	u.LowIndex = new(big.Int).SetUint64(w.LowIndex)
	for i := range w.LowPath {
		u.LowPath[i] = new(big.Int).Set(&w.LowPath[i])
	}
	return u
}

func TestKeyRegisterWritesTheRecord(t *testing.T) {
	member := pkField(t, allowedKey)
	tests := []struct {
		name   string
		seed   func(*spptest.MemberRegistry)
		tamper func(*KeyRegisterCircuit)
		passes bool
	}{
		{"new member", func(*spptest.MemberRegistry) {}, nil, true},
		{"listed member keeps its lists", func(m *spptest.MemberRegistry) {
			m.Update(t, member, big.NewInt(listMask(listAllow, listApproval)), big.NewInt(0))
		}, nil, true},
		{"member behind other records", func(m *spptest.MemberRegistry) {
			m.Update(t, pkField(t, approvedKey), big.NewInt(1), big.NewInt(0))
			m.Update(t, pkField(t, blockedKey), big.NewInt(1), big.NewInt(0))
		}, nil, true},
		{"new member granting itself lists", func(*spptest.MemberRegistry) {}, func(c *KeyRegisterCircuit) {
			c.Lists = big.NewInt(1)
		}, false},
		{"listed member dropping its lists", func(m *spptest.MemberRegistry) {
			m.Update(t, member, big.NewInt(listMask(listAllow)), big.NewInt(0))
		}, func(c *KeyRegisterCircuit) { c.Lists = big.NewInt(0) }, false},
		{"registered key overwritten", func(m *spptest.MemberRegistry) {
			m.RegisterKey(t, member, big.NewInt(0x0b), big.NewInt(0x0c))
		}, nil, false},
		{"another member's record", func(*spptest.MemberRegistry) {}, func(c *KeyRegisterCircuit) {
			c.Member = pkField(t, approvedKey)
		}, false},
		{"new root misreported", func(*spptest.MemberRegistry) {}, func(c *KeyRegisterCircuit) {
			c.RegistryNewRoot = big.NewInt(1)
		}, false},
		{"secret with a nonzero lead byte", func(*spptest.MemberRegistry) {}, func(c *KeyRegisterCircuit) {
			c.NullifierSecret[0] = 1
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			members := spptest.NewMemberRegistry(t, registry.Height)
			tt.seed(members)
			c := registerKeyAssignment(t, members, member)
			if tt.tamper != nil {
				tt.tamper(c)
			}
			witness, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := registerSystem(t).IsSolved(witness); (err == nil) != tt.passes {
				t.Fatalf("passes=%v, solve=%v", tt.passes, err)
			}
		})
	}
}

// The register_key statement reads the escrow key the policy escrow check expects.
func TestRegisteredKeyEscrowsThePolicyOutput(t *testing.T) {
	s := newStatement(t, defaultFixture())
	output := s.outputs[0]
	owner, nullifierPk := spptest.AsBigInt(output.OwnerPkHash), spptest.AsBigInt(output.NullifierPk)
	ctHash := big.NewInt(0xc0)
	s.members.RegisterKey(t, owner, nullifierPk, ctHash)
	opening := s.members.Opening(owner)
	if !opening.Present || opening.Record.EscrowKey.Cmp(spptest.MustPoseidon(t, 3, []*big.Int{nullifierPk, ctHash})) != 0 {
		t.Fatal("the record does not carry the escrow key")
	}
	if spptest.AsBigInt(output.Domain).Int64() != protocol.UtxoDomain {
		t.Fatal("the first output is no UTXO")
	}
	s.ctHashes = []*big.Int{ctHash}
	s.keyEscrow = true
	solve(t, testConstraintSystem(t), s.assignment(t))
}
