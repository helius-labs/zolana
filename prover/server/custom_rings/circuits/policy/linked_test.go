package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	base "github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// TestLinkedShapes keeps every member-policy proof comfortably below 100k
// constraints and rejects a commitment-bearing plain proof shape.
func TestLinkedShapes(t *testing.T) {
	circuits := []struct {
		name  string
		c     frontend.Circuit
		limit int
	}{
		{"facts 0..2", NewLinkedFactGroup(0), 85_000},
		{"facts 3..5", NewLinkedFactGroup(1), 85_000},
		{"facts 6..7", NewLinkedFactGroup(2), 65_000},
		{"facts 8..9", NewLinkedFactGroup(3), 65_000},
		{"policy core", &LinkedPolicyCoreCircuit{}, 95_000},
		{"key escrow", &LinkedEscrowCircuit{}, 55_000},
		{"auditor", &base.CustomRingBaseCircuit{}, 95_000},
	}
	for _, row := range circuits {
		t.Run(row.name, func(t *testing.T) {
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, row.c)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%d constraints", cs.GetNbConstraints())
			if got := cs.GetNbConstraints(); got >= row.limit {
				t.Fatalf("%d constraints exceeds %d", got, row.limit)
			}
			commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
			want := 0
			if row.name == "auditor" {
				want = 1
			}
			if !ok || len(commitments) != want {
				t.Fatalf("expected %d commitments, got %v", want, cs.GetCommitments())
			}
		})
	}
}

// TestLinkedPolicyWitness proves the same transaction under all linked
// statements and rejects replacing one authenticated fact group.
func TestLinkedPolicyWitness(t *testing.T) {
	f := defaultFixture()
	s := newStatement(t, f)
	s.escrowOutputs(t)
	full := s.assignment(t, f.facts())
	targets := s.revocationTargets(f.facts())
	publicFields := s.policyChainElements(t, f.facts())
	treeHash := publicFields[12]
	var groups [4]*LinkedFactGroupCircuit
	var digests [4]*big.Int
	for group, start := range linkedFactStarts {
		g := NewLinkedFactGroup(group)
		g.PrivateTxHash = full.PrivateTxHash
		g.LinkBlinding = full.PrivateTxBlinding
		g.TreeSlots = full.TreeSlots
		g.AddressTreeID = full.AddressTreeID
		g.Sources = full.Sources
		copy(g.Facts, full.ListFacts[start:start+linkedFactCounts[group]])
		digests[group] = hostGroupDigest(t, full.PrivateTxBlinding, start, g.Facts, targets[start:], full.Sources)
		g.GroupDigest = digests[group]
		g.PublicInputHash = spptest.MustHashChain(t, []*big.Int{
			packedASCII(linkedGroupDomain), spptest.AsBigInt(full.PrivateTxHash),
			big.NewInt(int64(start)), digests[group], treeHash, spptest.AsBigInt(full.AddressTreeID),
		})
		groups[group] = g
	}
	outputDigest := hostOutputDigest(t, full)

	core := &LinkedPolicyCoreCircuit{Policy: *full, OutputDigest: outputDigest}
	for group := range digests {
		core.GroupDigests[group] = digests[group]
	}
	for i, fact := range full.ListFacts {
		core.Facts[i] = FactSummaryWires{
			Enabled: fact.Enabled, TreeSlot: fact.TreeSlot, Mode: fact.Mode,
			ListId: fact.ListId, Member: fact.Member, RevocationTarget: targets[i],
		}
	}
	coreFields := []*big.Int{
		packedASCII(linkedCoreDomain), spptest.AsBigInt(full.PrivateTxHash), publicFields[11], treeHash,
		spptest.AsBigInt(full.AddressTreeID), spptest.AsBigInt(full.RingID),
		spptest.AsBigInt(full.NamespaceOwnerHash), spptest.AsBigInt(full.WindowIndex),
		spptest.AsBigInt(full.ApprovalRequired), spptest.AsBigInt(full.KeyEscrow),
		spptest.AsBigInt(full.KeyRegistryRoot), s.revocationTreeIndexes(f.facts()),
	}
	coreFields = append(coreFields, targets...)
	coreFields = append(coreFields, digests[:]...)
	coreFields = append(coreFields, outputDigest)
	core.Policy.PublicInputHash = spptest.MustHashChain(t, coreFields)
	t.Logf("linked group0 %064x", spptest.AsBigInt(groups[0].PublicInputHash))
	t.Logf("linked core %064x", spptest.AsBigInt(core.Policy.PublicInputHash))

	escrow := &LinkedEscrowCircuit{
		PrivateTxHash: full.PrivateTxHash, OutputDigest: outputDigest, LinkBlinding: full.PrivateTxBlinding,
		NamespaceOwnerHash: full.NamespaceOwnerHash, KeyEscrow: full.KeyEscrow,
		KeyRegistryRoot: full.KeyRegistryRoot, OutputKeys: full.OutputKeys,
	}
	for i := range escrow.Outputs {
		utxo := hostOutputUtxo(full, i)
		escrow.Outputs[i] = LinkedEscrowOutputWires{
			OwnerPkHash: full.Outputs[i].OwnerPkHash,
			NullifierPk: full.Outputs[i].NullifierPk, Utxo: utxo,
		}
	}
	escrow.PublicInputHash = spptest.MustHashChain(t, []*big.Int{
		packedASCII(linkedEscrowDomain), spptest.AsBigInt(full.PrivateTxHash), outputDigest,
		spptest.AsBigInt(full.NamespaceOwnerHash), spptest.AsBigInt(full.KeyEscrow),
		spptest.AsBigInt(full.KeyRegistryRoot),
	})
	t.Logf("linked escrow %064x", spptest.AsBigInt(escrow.PublicInputHash))

	for group, witness := range groups {
		t.Run("group "+string(rune('0'+group)), func(t *testing.T) {
			linkedSolve(t, NewLinkedFactGroup(group), witness)
		})
	}
	linkedSolve(t, &LinkedPolicyCoreCircuit{}, core)
	linkedSolve(t, &LinkedEscrowCircuit{}, escrow)

	wrong := *core
	wrong.GroupDigests[0] = digests[1]
	linkedReject(t, &LinkedPolicyCoreCircuit{}, &wrong)
	wrong = *core
	wrong.Facts[0].RevocationTarget = big.NewInt(1)
	linkedReject(t, &LinkedPolicyCoreCircuit{}, &wrong)
	wrongGroup := *groups[0]
	wrongGroup.TreeSlots[0].UtxoRoot = big.NewInt(1)
	linkedReject(t, NewLinkedFactGroup(0), &wrongGroup)
	wrongGroup = *groups[0]
	wrongGroup.PrivateTxHash = big.NewInt(1)
	linkedReject(t, NewLinkedFactGroup(0), &wrongGroup)
	wrongEscrow := *escrow
	wrongEscrow.LinkBlinding = big.NewInt(1)
	linkedReject(t, &LinkedEscrowCircuit{}, &wrongEscrow)
	wrongGroup = *groups[0]
	wrongGroup.LinkBlinding = big.NewInt(1)
	linkedReject(t, NewLinkedFactGroup(0), &wrongGroup)
	escrow.OutputKeys[0].CtHash = big.NewInt(42)
	linkedReject(t, &LinkedEscrowCircuit{}, escrow)
}

// linkedSolve verifies the full R1CS assignment for a linked subproof.
func linkedSolve(t *testing.T, circuit, assignment frontend.Circuit) {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(w); err != nil {
		t.Fatal(err)
	}
}

// linkedReject requires the altered witness to fail the same R1CS.
func linkedReject(t *testing.T, circuit, assignment frontend.Circuit) {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(w); err == nil {
		t.Fatal("altered linked proof accepted")
	}
}

// hostGroupDigest mirrors the fixed two-block Poseidon fact commitment.
func hostGroupDigest(t *testing.T, blinding frontend.Variable, start int, facts []ListFactWires, targets []*big.Int, sources [NSources]SourceWires) *big.Int {
	t.Helper()
	fields := []*big.Int{packedASCII(linkedGroupDomain), spptest.AsBigInt(blinding), big.NewInt(int64(start))}
	for i, fact := range facts {
		enabled := spptest.AsBigInt(fact.Enabled)
		gate := func(value frontend.Variable) *big.Int {
			if enabled.Sign() == 0 {
				return big.NewInt(0)
			}
			return spptest.AsBigInt(value)
		}
		owner := big.NewInt(0)
		if enabled.Sign() != 0 {
			for _, source := range sources {
				if spptest.AsBigInt(source.ListId).Cmp(spptest.AsBigInt(fact.ListId)) == 0 {
					owner = spptest.AsBigInt(source.OwnerHash)
					break
				}
			}
		}
		fields = append(fields, enabled, gate(fact.TreeSlot), gate(fact.Mode),
			gate(fact.ListId), gate(fact.Member), gate(targets[i]), owner)
	}
	split := min(13, len(fields))
	hash := spptest.MustPoseidon(t, split+1, fields[:split])
	if split < len(fields) {
		hash = spptest.MustPoseidon(t, len(fields)-split+2, append([]*big.Int{hash}, fields[split:]...))
	}
	return hash
}

// hostOutputUtxo mirrors selection of UTXO output slots including records.
func hostOutputUtxo(c *CustomRingPolicyCircuit, index int) *big.Int {
	count := 0
	for i, bit := range c.OutputCountSelected {
		if spptest.AsBigInt(bit).Sign() != 0 {
			count = i + 1
		}
	}
	if index < count && spptest.AsBigInt(c.Outputs[index].Domain).Int64() == shared.UtxoDomain {
		return big.NewInt(1)
	}
	return big.NewInt(0)
}

// hostOutputDigest mirrors the core and escrow output commitment.
func hostOutputDigest(t *testing.T, c *CustomRingPolicyCircuit) *big.Int {
	t.Helper()
	fields := []*big.Int{packedASCII(linkedOutputDomain), spptest.AsBigInt(c.PrivateTxBlinding)}
	for i, output := range c.Outputs {
		utxo := hostOutputUtxo(c, i)
		owner, nullifier := big.NewInt(0), big.NewInt(0)
		if utxo.Sign() != 0 {
			owner = spptest.AsBigInt(output.OwnerPkHash)
			nullifier = spptest.AsBigInt(output.NullifierPk)
		}
		fields = append(fields, spptest.MustPoseidon(t, 5, []*big.Int{
			big.NewInt(int64(i)), utxo, owner, nullifier,
		}))
	}
	return spptest.MustHashChain(t, fields)
}
