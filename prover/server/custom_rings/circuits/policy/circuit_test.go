package policy

import (
	"fmt"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// The host side of this test recomputes the whole statement outside the
// circuit, the audit block with crypto/ecdh and crypto/aes, the member
// registries and the policy hashing with the same iden3 Poseidon the Rust twins
// use. Solving the compiled R1CS against that witness is the cross-check that
// the circuit computes what custom-rings/policy will recompute.

// The policy the fixture proves against.
const (
	listAllow    = 1
	listBlock    = 2
	listFrozen   = 3
	listApproval = 7

	guardThreshold = 2000
	transferAmount = 1000
)

var (
	compileOnce sync.Once
	compiledCs  constraint.ConstraintSystem
	compileErr  error
)

func testConstraintSystem(t *testing.T) constraint.ConstraintSystem {
	t.Helper()
	compileOnce.Do(func() {
		start := time.Now()
		compiledCs, compileErr = frontend.Compile(
			ecc.BN254.ScalarField(),
			r1cs.NewBuilder,
			&CustomRingPolicyCircuit{},
			frontend.WithCompressThreshold(300),
		)
		if compileErr == nil {
			t.Logf("compiled in %s: %d constraints, %d internal variables, %d secret variables",
				time.Since(start).Round(time.Millisecond),
				compiledCs.GetNbConstraints(),
				compiledCs.GetNbInternalVariables(),
				compiledCs.GetNbSecretVariables())
		}
	})
	if compileErr != nil {
		t.Fatalf("compile: %v", compileErr)
	}
	return compiledCs
}

func TestCircuitCommitmentShape(t *testing.T) {
	cs := testConstraintSystem(t)

	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok {
		t.Fatalf("unexpected commitments type %T", cs.GetCommitments())
	}
	// groth16-solana's BSB22 verifier supports exactly one commitment over
	// private wires, a committed public wire makes the vk parser reject the
	// key with Bsb22UnsupportedMultiCommitment.
	if len(commitments) != 1 {
		t.Fatalf("expected 1 BSB22 commitment, got %d", len(commitments))
	}
	if got := commitments[0].NbPublicCommitted; got != 0 {
		t.Fatalf("expected 0 public committed wires, got %d", got)
	}
	t.Logf("BSB22: 1 commitment over %d private wires", len(commitments[0].PrivateCommitted))
}

func TestConstants(t *testing.T) {
	const tag = "zolana:ring-policy:policy:v1"
	var padded [32]byte
	copy(padded[32-len(tag):], tag)
	if policyTableDomain.Cmp(new(big.Int).SetBytes(padded[:])) != 0 {
		t.Fatalf("domain %q packs to %s", tag, policyTableDomain)
	}
}

func TestCircuitSolvesValidWitness(t *testing.T) {
	cs := testConstraintSystem(t)

	solve(t, cs, validAssignment(t))
}

// A require-any group is satisfied when the subject is present in any one of
// the masked lists, the recipient sits on Allow within an Allow-or-Block group.
func TestCircuitSolvesGroupRule(t *testing.T) {
	cs := testConstraintSystem(t)

	f := defaultFixture()
	f.outputOwnerMask = listMask(listBlock, listAllow)
	solve(t, cs, buildAssignment(t, f))
}

// An any_of rule passes through either alternative, a recipient never added
// to Block through the absent branch, a recipient on both Approval and Block
// through the present branch.
func TestCircuitSolvesMixedModeRule(t *testing.T) {
	cs := testConstraintSystem(t)

	absent := mixedFixture()
	solve(t, cs, buildAssignment(t, absent))

	present := mixedFixture()
	present.recipient = approvedKey
	solve(t, cs, buildAssignment(t, present))
}

// Two outputs to one recipient whose total stays at or below the threshold are
// exempt together, aggregation does not over-reject a legitimate split.
func TestCircuitSolvesAggregatedGuard(t *testing.T) {
	cs := testConstraintSystem(t)

	f := defaultFixture()
	f.amount = guardThreshold / 2
	f.secondAmount = guardThreshold / 2
	solve(t, cs, buildAssignment(t, f))
}

func TestCircuitSolvesPerAssetLimits(t *testing.T) {
	cs := testConstraintSystem(t)

	f := defaultFixture()
	f.amount = 900
	f.secondAmount = 1500
	f.secondTransferred = fill(0xe5)
	f.secondInlineAsset = fill(0xe5)
	f.perAssetLimits = []uint64{1000, 2000}
	solve(t, cs, buildAssignment(t, f))
}

func TestCircuitSolvesRulesFreeWitness(t *testing.T) {
	cs := testConstraintSystem(t)

	f := defaultFixture()
	f.rulesFree = true
	solve(t, cs, buildAssignment(t, f))
}

// The Frozen list is read from the curator registry, a Frozen bit in the ring's own registry is ignored.
func TestCuratorListsComeFromTheCuratorRegistry(t *testing.T) {
	cs := testConstraintSystem(t)

	s := newStatement(t, defaultFixture())
	s.setLists(t, s.members, s.sender, listMask(listFrozen))
	solve(t, cs, s.assignment(t))

	s.setLists(t, s.curator, s.sender, listMask(listFrozen))
	rejectAssignment(t, s.assignment(t))
}

func TestCircuitRejectsTamperedWitness(t *testing.T) {
	cs := testConstraintSystem(t)

	tests := []struct {
		name  string
		build func(*testing.T) *CustomRingPolicyCircuit
	}{
		{
			name: "rule dropped from the table",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.PolicyLen = big.NewInt(3)
				return c
			},
		},
		{
			name: "recipient lists tampered",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.Subjects[NInputs].Lists = big.NewInt(listMask(listAllow, listApproval))
				return c
			},
		},
		{
			name: "recipient record claimed absent",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.Subjects[NInputs].Present = big.NewInt(0)
				c.Subjects[NInputs].Lists = big.NewInt(0)
				return c
			},
		},
		{
			name: "recipient opened at another index",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.Subjects[NInputs].Index = big.NewInt(0)
				return c
			},
		},
		{
			name: "recipient path does not open the registry root",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.Subjects[NInputs].Path[0] = big.NewInt(1)
				return c
			},
		},
		{
			name: "stale registry root",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				s := newStatement(t, defaultFixture())
				c := s.assignment(t)
				c.MemberRegistryRoot = new(big.Int).Add(s.members.Root(), big.NewInt(1))
				s.rebind(t, c)
				return c
			},
		},
		{
			name: "stale curator root",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				s := newStatement(t, defaultFixture())
				c := s.assignment(t)
				c.ForeignRoot = new(big.Int).Add(s.curator.Root(), big.NewInt(1))
				s.rebind(t, c)
				return c
			},
		},
		{
			name: "another member's record for the recipient",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				s := newStatement(t, defaultFixture())
				c := s.assignment(t)
				c.Subjects[NInputs] = openingWires(s.members.Opening(pkField(t, approvedKey)))
				return c
			},
		},
		{
			name: "curator slot dropped from the map",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.dropCuratorSlot = true
				return buildAssignment(t, f)
			},
		},
		{
			name: "live source slots swapped in the witness",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.Sources[listAllow-1], c.Sources[listFrozen-1] =
					c.Sources[listFrozen-1], c.Sources[listAllow-1]
				return c
			},
		},
		{
			name: "live listId duplicated into a second slot in the witness",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.Sources[4] = c.Sources[listFrozen-1]
				return c
			},
		},
		{
			name: "curator slots naming two registries",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				s := newStatement(t, defaultFixture())
				s.sources[listBlock-1].registry = big.NewInt(0x1234)
				return s.assignment(t)
			},
		},
		{
			name: "foreign root without a curator",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.rulesFree = true
				s := newStatement(t, f)
				c := s.assignment(t)
				c.ForeignRoot = s.curator.Root()
				s.rebind(t, c)
				return c
			},
		},
		{
			name: "frozen sender",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				s := newStatement(t, defaultFixture())
				s.setLists(t, s.curator, s.sender, listMask(listFrozen))
				return s.assignment(t)
			},
		},
		{
			name: "guard bypassed above the threshold",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.amount = guardThreshold + 1
				return buildAssignment(t, f)
			},
		},
		{
			name: "guard bypassed by structuring below the threshold",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.amount = guardThreshold - 500
				f.secondAmount = guardThreshold - 500
				return buildAssignment(t, f)
			},
		},
		{
			name: "per-asset guard bypassed above one asset limit",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.amount = 900
				f.secondAmount = 1500
				f.secondTransferred = fill(0xe5)
				f.secondInlineAsset = fill(0xe5)
				f.perAssetLimits = []uint64{800, 2000}
				return buildAssignment(t, f)
			},
		},
		{
			name: "per-asset guard bypassed by splitting one asset",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.amount = 600
				f.secondAmount = 600
				f.perAssetLimits = []uint64{1000}
				return buildAssignment(t, f)
			},
		},
		{
			name: "per-asset guard used with an unconfigured asset",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.amount = 500
				f.secondAmount = 1
				f.secondTransferred = fill(0xe5)
				f.perAssetLimits = []uint64{1000}
				return buildAssignment(t, f)
			},
		},
		{
			name: "output owner group excludes the recipient's list",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.outputOwnerMask = listMask(listBlock, listApproval)
				return buildAssignment(t, f)
			},
		},
		{
			name: "asset outside the registry allowlist",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.inlineAsset = fill(0xe5)
				return buildAssignment(t, f)
			},
		},
		{
			name: "legacy inline asset rule",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				s := newStatement(t, defaultFixture())
				s.rules[2].mask = 0
				return s.assignment(t)
			},
		},
		{
			name: "dummy input reclassified as a utxo",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.Inputs[1].Domain = big.NewInt(protocol.UtxoDomain)
				return c
			},
		},
		{
			name: "output count understated",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.NOut = big.NewInt(1)
				return c
			},
		},
		{
			name: "unclamped tx secret",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.keys = func(k ringaudit.Keys) ringaudit.Keys {
					return k.WithRawTxScalar(t, [32]byte{})
				}
				return buildAssignment(t, f)
			},
		},
		{
			name: "invalid viewing key tag",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.keys = func(k ringaudit.Keys) ringaudit.Keys {
					return k.WithInvalidTxTag()
				}
				return buildAssignment(t, f)
			},
		},
		{
			name: "asset rule with overlapping alternatives",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.inlineAltMask = listMask(listAllow)
				return buildAssignment(t, f)
			},
		},
		{
			name: "rule mode outside present and absent",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				// The guard exempts the recipient, only the mode assertion rejects.
				f := defaultFixture()
				f.guardedMode = 3
				return buildAssignment(t, f)
			},
		},
		{
			name: "alt mask bit past the eighth list",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.outputOwnerAltMask = 1 << NSources
				return buildAssignment(t, f)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			witness, err := frontend.NewWitness(test.build(t), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatalf("new witness: %v", err)
			}
			if err := cs.IsSolved(witness); err == nil {
				t.Fatal("expected the tampered witness to be rejected")
			}
		})
	}
}

// TestPrintPolicyVectors prints the host recompute for transplanting into the
// Rust vector tests.
func TestPrintPolicyVectors(t *testing.T) {
	if os.Getenv("PRINT_POLICY_VECTORS") != "1" {
		t.Skip("PRINT_POLICY_VECTORS=1 prints the Rust vector constants")
	}
	s := newStatement(t, defaultFixture())

	fmt.Printf("own_owner_hash       %s\n", hex32(s.ownOwnerHash))
	fmt.Printf("curator_registry     %s\n", hex32(s.curatorRegistry))
	fmt.Printf("policy_hash          %s\n", hex32(s.policyHash))
	fmt.Printf("member_registry_root %s\n", hex32(s.members.Root()))
	fmt.Printf("curator_root         %s\n", hex32(s.curator.Root()))
	fmt.Printf("private_tx_hash      %s\n", hex32(s.privateTxHash))
	fmt.Printf("public_input_hash    %s\n", hex32(s.publicInputHash))

	fmt.Printf("empty_policy_hash    %s\n", hex32(hostPolicy{sources: emptySources()}.hash(t)))
	oneMap := emptySources()
	oneMap[listAllow-1] = source{listId: listAllow, registry: big.NewInt(0)}
	oneRule := []rule{{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listAllow)}}
	fmt.Printf("one_rule_policy_hash %s\n", hex32(hostPolicy{rules: oneRule, sources: oneMap}.hash(t)))
	twoMap := oneMap
	twoMap[listFrozen-1] = source{listId: listFrozen, registry: s.curatorRegistry}
	twoRules := append(oneRule, rule{subject: SubjectSender, mode: ModeAbsent, mask: listMask(listFrozen)})
	fmt.Printf("two_rule_policy_hash %s\n", hex32(hostPolicy{rules: twoRules, sources: twoMap}.hash(t)))
	mixedMap := emptySources()
	mixedMap[listBlock-1] = source{listId: listBlock, registry: big.NewInt(0)}
	mixedMap[listApproval-1] = source{listId: listApproval, registry: big.NewInt(0)}
	mixedRule := []rule{{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listApproval), altMask: listMask(listBlock)}}
	fmt.Printf("mixed_rule_policy_hash %s\n", hex32(hostPolicy{rules: mixedRule, sources: mixedMap}.hash(t)))
	perAssetRule := []rule{{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listAllow), guardTag: GuardAboveAmountByAsset}}
	fmt.Printf("per_asset_policy_hash %s\n", hex32(hostPolicy{
		rules:        perAssetRule,
		inlineAssets: []*big.Int{assetField(t, fill(0xd4))},
		inlineLimits: []uint64{123},
		sources:      oneMap,
	}.hash(t)))
	limitRows := []limitRow{{asset: assetField(t, fill(0xd4)), cap: 5000, cosign: 600}}
	fmt.Printf("limits_policy_hash   %s\n", hex32(hostPolicy{rules: oneRule, sources: oneMap, limits: limitRows}.hash(t)))
	lf := defaultFixture()
	lf.limits = limitFixtureDefault()
	lf.limits.cosignAbove = 600
	lf.limits.approval = true
	lv := newStatement(t, lf)
	fmt.Printf("limits_public_input_hash %s\n", hex32(lv.publicInputHash))
}

func solve(t *testing.T, cs constraint.ConstraintSystem, assignment *CustomRingPolicyCircuit) {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	if err := cs.IsSolved(witness); err != nil {
		t.Fatalf("solve: %v", err)
	}
}

func TestCircuitAcceptsAMovedDummyInput(t *testing.T) {
	c := validAssignment(t)
	c.Inputs[0], c.Inputs[1] = c.Inputs[1], c.Inputs[0]
	c.Subjects[0], c.Subjects[1] = c.Subjects[1], c.Subjects[0]
	c.ForeignSubjects[0], c.ForeignSubjects[1] = c.ForeignSubjects[1], c.ForeignSubjects[0]
	witness, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	if err := testConstraintSystem(t).IsSolved(witness); err != nil {
		t.Fatalf("a dummy input moved ahead of the spend was rejected: %v", err)
	}
}

func validAssignment(t *testing.T) *CustomRingPolicyCircuit {
	t.Helper()
	return buildAssignment(t, defaultFixture())
}

// fixture is the knob set of one statement, a tamper row needing a
// self-consistent witness rebuilds with one knob changed.
type fixture struct {
	amount uint64
	// 0 keeps one real output, else a second to the same recipient
	secondAmount uint64
	// 0 keeps the single Allow rule, else the OutputOwner rule's list mask
	outputOwnerMask int64
	// lists satisfying the OutputOwner rule in the opposite mode
	outputOwnerAltMask int64
	// 0 keeps Present, else the guarded Approval rule's mode
	guardedMode       int64
	inlineAltMask     int64 // an alternative list mask on the asset rule
	recipient         [32]byte
	transferred       [32]byte
	inlineAsset       [32]byte
	secondTransferred [32]byte
	secondInlineAsset [32]byte
	perAssetLimits    []uint64
	rulesFree         bool
	dropCuratorSlot   bool
	keys              func(ringaudit.Keys) ringaudit.Keys
	// nil keeps outflow limits off
	limits *limitFixture
}

type limitFixture struct {
	cap         uint64
	cosignAbove uint64
	// a same-owner output, inside the ring unless exit is set
	change uint64
	exit   bool
	// a second input of another owner
	secondSender bool
	approval     bool
	// extra rows beside the transferred asset
	rows []limitRow
	// the sender's change satisfies no output owner rule, the change cases run rule free
	rulesFree bool
}

const limitCap = 5000

func limitFixtureDefault() *limitFixture {
	return &limitFixture{cap: limitCap}
}

type limitRow struct {
	asset  *big.Int
	cap    uint64
	cosign uint64
}

// Member keys of the fixture ring, the recipient knob picks among them.
var (
	allowedKey  = fill(0xa1)
	approvedKey = fill(0xf6)
	blockedKey  = fill(0xc3)
	senderKey   = fill(0xb2)
)

func defaultFixture() fixture {
	return fixture{
		amount:      transferAmount,
		recipient:   allowedKey,
		transferred: fill(0xd4),
		inlineAsset: fill(0xd4),
	}
}

// mixedFixture swaps the Allow rule for any_of(OutputOwner, present Approval,
// absent Block).
func mixedFixture() fixture {
	f := defaultFixture()
	f.outputOwnerMask = listMask(listApproval)
	f.outputOwnerAltMask = listMask(listBlock)
	return f
}

// source is one host-side slot of the positional policy source map.
type source struct {
	listId int64
	// registry is the curator registry address, zero for the ring's own lists.
	registry *big.Int
}

func emptySources() [NSources]source {
	var out [NSources]source
	for i := range out {
		out[i] = source{listId: 0, registry: big.NewInt(0)}
	}
	return out
}

// rule mirrors ring_policy::Rule, packed by ring_policy::Rule::encoded.
type rule struct {
	subject   int64
	mode      int64
	mask      int64
	altMask   int64
	guardTag  int64
	threshold uint64
}

func listMask(ids ...int64) int64 {
	var mask int64
	for _, id := range ids {
		mask |= 1 << (id - 1)
	}
	return mask
}

func (r rule) packed() *big.Int {
	packed := new(big.Int).Lsh(big.NewInt(r.altMask), 64)
	packed.Or(packed, new(big.Int).SetUint64(r.threshold))
	for _, part := range []int64{r.guardTag, r.mask, r.mode, r.subject} {
		packed.Or(packed.Lsh(packed, 8), big.NewInt(part))
	}
	return packed
}

type statement struct {
	ownOwnerHash    *big.Int
	curatorRegistry *big.Int
	sources         [NSources]source
	rules           []rule
	inlineAssets    []*big.Int
	inlineLimits    []uint64
	limits          []limitRow
	policyHash      *big.Int

	// The ring every recipient note and change output stays in, ringID is HashBytes of it.
	ringProgramID [32]byte
	ringID        *big.Int
	approval      bool
	// assets maps an output asset field back to the mint address its body delivers.
	assets map[string][32]byte

	sender *big.Int
	// members is the ring's own registry, curator the one its curator sources read.
	members *spptest.MemberRegistry
	curator *spptest.MemberRegistry

	keyEscrow bool
	// Aligned with outputs, nil for an output without an escrowed key.
	ctHashes []*big.Int

	inputs     []UtxoWires
	outputs    []UtxoWires
	shortAudit bool

	addressChain      *big.Int
	privateTxBlinding *big.Int
	privateTxHash     *big.Int
	publicInputHash   *big.Int

	keys ringaudit.Keys
	// anonymous discloses the sender and recipient keys, recipientKeys follow the outputs.
	anonymous     bool
	senderKey     [32]byte
	recipientKeys [NOutputs][32]byte
}

// newStatement builds a ring whose registry lists the recipient on Allow, a
// cleared member off Block and a second recipient on both Approval and Block,
// a curator registry that does not freeze the sender, a policy demanding the
// first three plus a guarded Approval rule, and a two-in two-out transaction
// that satisfies them. The Frozen list is sourced from the curator registry,
// every other list from the ring's own.
func newStatement(t *testing.T, f fixture) *statement {
	t.Helper()
	s := &statement{}
	if v := f.limits; v != nil && v.rulesFree {
		f.rulesFree = true
	}

	s.ownOwnerHash = spptest.MustOwnerHash(t,
		pkField(t, fill(0x11)),
		spptest.MustNullifierPk(t, big.NewInt(0)),
	)
	s.curatorRegistry = pkField(t, fill(0x12))
	s.sources = emptySources()
	for _, listId := range []int64{listAllow, listBlock, listApproval} {
		s.sources[listId-1] = source{listId: listId, registry: big.NewInt(0)}
	}
	s.sources[listFrozen-1] = source{listId: listFrozen, registry: s.curatorRegistry}
	if f.dropCuratorSlot {
		s.sources[listFrozen-1] = source{listId: 0, registry: big.NewInt(0)}
	}

	allowed := pkField(t, allowedKey)
	s.sender = pkField(t, senderKey)
	blocked := pkField(t, blockedKey)
	approved := pkField(t, approvedKey)
	asset := assetField(t, f.transferred)

	s.members = spptest.NewMemberRegistry(t, registry.Height)
	s.members.Update(t, allowed, big.NewInt(listMask(listAllow)), big.NewInt(0))
	s.members.Update(t, approved, big.NewInt(listMask(listApproval, listBlock)), big.NewInt(0))
	// A cleared member keeps its record with the Block bit removed.
	s.members.Update(t, blocked, big.NewInt(listMask(listBlock)), big.NewInt(0))
	s.members.Update(t, blocked, big.NewInt(0), big.NewInt(0))
	s.curator = spptest.NewMemberRegistry(t, registry.Height)
	s.curator.Update(t, pkField(t, fill(0xc4)), big.NewInt(listMask(listFrozen)), big.NewInt(0))

	s.rules = []rule{
		{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listAllow)},
		{subject: SubjectSender, mode: ModeAbsent, mask: listMask(listFrozen)},
		{subject: SubjectAsset, mode: ModePresent, mask: listMask(listAllow)},
		{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listApproval), guardTag: GuardAboveAmount, threshold: guardThreshold},
	}
	s.inlineAssets = []*big.Int{assetField(t, f.inlineAsset)}
	if f.secondInlineAsset != [32]byte{} {
		s.inlineAssets = append(s.inlineAssets, assetField(t, f.secondInlineAsset))
	}
	for _, mint := range s.inlineAssets {
		s.members.Update(t, mint, big.NewInt(listMask(listAllow)), big.NewInt(0))
	}
	if f.perAssetLimits != nil {
		s.rules[3].guardTag = GuardAboveAmountByAsset
		s.rules[3].threshold = 0
		s.inlineLimits = f.perAssetLimits
	} else {
		s.inlineAssets = nil
	}
	if f.outputOwnerMask != 0 {
		s.rules[0].mask = f.outputOwnerMask
	}
	s.rules[0].altMask = f.outputOwnerAltMask
	s.rules[2].altMask = f.inlineAltMask
	if f.guardedMode != 0 {
		s.rules[3].mode = f.guardedMode
	}
	if f.rulesFree {
		s.rules = nil
		s.inlineAssets = nil
		s.sources = emptySources()
	}
	s.ringProgramID = ringaudit.Repeat(0x5a)
	s.ringID = ringaudit.HashBytes(t, s.ringProgramID[:])
	if v := f.limits; v != nil {
		s.approval = v.approval
		s.limits = append([]limitRow{{asset: asset, cap: v.cap, cosign: v.cosignAbove}}, v.rows...)
	}
	s.policyHash = s.policy().hash(t)

	s.keys = ringaudit.DefaultKeys(t)
	if f.keys != nil {
		s.keys = f.keys(s.keys)
	}
	secondAsset := asset
	s.assets = map[string][32]byte{asset.String(): f.transferred}
	if f.secondTransferred != [32]byte{} {
		secondAsset = assetField(t, f.secondTransferred)
		s.assets[secondAsset.String()] = f.secondTransferred
	}
	s.senderKey = senderKey
	s.recipientKeys = [NOutputs][32]byte{f.recipient, f.recipient}
	s.buildTransaction(t, pkField(t, f.recipient), s.sender, asset, secondAsset, f.amount, f.secondAmount)
	if v := f.limits; v != nil {
		s.shapeLimits(t, v, s.sender)
	}
	return s
}

// setLists rewrites a member's lists in one registry, keeping its escrow key.
func (s *statement) setLists(t *testing.T, members *spptest.MemberRegistry, member *big.Int, lists int64) {
	t.Helper()
	escrow := big.NewInt(0)
	if index, present := members.Find(member); present {
		escrow = members.Opening(member).Record.EscrowKey
		_ = index
	}
	members.Update(t, member, big.NewInt(lists), escrow)
}

// anyForeign is set when a source names the curator registry.
func (s *statement) anyForeign() bool {
	for _, slot := range s.sources {
		if slot.registry.Sign() != 0 {
			return true
		}
	}
	return false
}

// The sender funds the change on top of the transfer, change inside the ring is excluded from the outflow.
func (s *statement) shapeLimits(t *testing.T, v *limitFixture, sender *big.Int) {
	t.Helper()
	s.inputs[0].Amount = new(big.Int).SetUint64(s.inputs[0].Amount.(*big.Int).Uint64() + v.change)
	if v.secondSender {
		other := s.inputs[0]
		other.OwnerPkHash = pkField(t, fill(0xb4))
		other.Blinding = big.NewInt(0x61)
		s.inputs[1] = other
	}
	if v.change > 0 {
		change := s.outputs[0]
		change.OwnerPkHash = sender
		change.Amount = new(big.Int).SetUint64(v.change)
		change.Blinding = big.NewInt(0x62)
		change.RingProgramID = s.ringID
		if v.exit {
			change.RingProgramID = big.NewInt(0)
		}
		s.outputs[1] = change
	}
	for i := range s.outputs {
		if s.outputs[i].Domain.(*big.Int).Int64() == protocol.UtxoDomain && s.outputs[i].OwnerPkHash != sender {
			s.outputs[i].RingProgramID = s.ringID
		}
	}
	s.updateHashes(t)
}

// addressTreeID is the raw id of the fixture's address tree, tree slot 0.
const addressTreeID = 7

// The policy proof binds the transaction's trees without reading them.
func (s *statement) treeSlots(t *testing.T) []protocol.TreeSlot {
	t.Helper()
	slots, err := protocol.PadTreeSlots(protocol.TreeSlot{ID: big.NewInt(addressTreeID), UtxoRoot: big.NewInt(0x1234), NullifierRoot: big.NewInt(0x5678)})
	if err != nil {
		t.Fatal(err)
	}
	return slots
}

func (s *statement) buildTransaction(
	t *testing.T,
	recipient, sender, asset, secondAsset *big.Int,
	amount, secondAmount uint64,
) {
	t.Helper()
	spent := UtxoWires{
		Domain:        big.NewInt(protocol.UtxoDomain),
		TreeID:        big.NewInt(0),
		OwnerPkHash:   sender,
		NullifierPk:   spptest.MustNullifierPk(t, big.NewInt(7)),
		Asset:         asset,
		Amount:        new(big.Int).SetUint64(amount),
		Blinding:      big.NewInt(0x51),
		DataHash:      big.NewInt(0),
		RingDataHash:  big.NewInt(0),
		RingProgramID: big.NewInt(0),
	}
	created := UtxoWires{
		Domain:        big.NewInt(protocol.UtxoDomain),
		TreeID:        big.NewInt(0),
		OwnerPkHash:   recipient,
		NullifierPk:   spptest.MustNullifierPk(t, big.NewInt(9)),
		Asset:         asset,
		Amount:        new(big.Int).SetUint64(amount),
		Blinding:      big.NewInt(0x52),
		DataHash:      big.NewInt(0),
		RingDataHash:  big.NewInt(0),
		RingProgramID: s.ringID,
	}
	s.inputs = []UtxoWires{spent, dummyOpening(t, 0x53)}
	// A second real output to the same recipient exercises the per-recipient
	// amount aggregation, else a dummy fills the slot.
	second := dummyOpening(t, 0x54)
	if secondAmount > 0 {
		second = UtxoWires{
			Domain:        big.NewInt(protocol.UtxoDomain),
			TreeID:        big.NewInt(0),
			OwnerPkHash:   recipient,
			NullifierPk:   spptest.MustNullifierPk(t, big.NewInt(11)),
			Asset:         secondAsset,
			Amount:        new(big.Int).SetUint64(secondAmount),
			Blinding:      big.NewInt(0x55),
			DataHash:      big.NewInt(0),
			RingDataHash:  big.NewInt(0),
			RingProgramID: s.ringID,
		}
	}
	s.outputs = []UtxoWires{created, second}

	s.addressChain = spptest.MustNonZeroHashChain(t, []*big.Int{big.NewInt(0), big.NewInt(0)})
	s.privateTxBlinding = big.NewInt(0x5b1d)
	s.updateHashes(t)
}

func buildAssignment(t *testing.T, f fixture) *CustomRingPolicyCircuit {
	t.Helper()
	return newStatement(t, f).assignment(t)
}

// assignment opens every live slot's owner in the registries and binds the statement.
func (s *statement) assignment(t *testing.T) *CustomRingPolicyCircuit {
	t.Helper()
	s.updateHashes(t)
	audit := s.auditStatement(t)
	c := &CustomRingPolicyCircuit{
		PublicInputHash:    s.publicInputHash,
		Audit:              audit.Audit,
		AddressChain:       s.addressChain,
		PrivateTxBlinding:  s.privateTxBlinding,
		Delivery:           audit.DeliveryWires(),
		AddressTreeID:      big.NewInt(addressTreeID),
		RingID:             s.ringID,
		NamespaceOwnerHash: s.ownOwnerHash,
		ApprovalRequired:   boolVar(s.approval),
		KeyEscrow:          boolVar(s.keyEscrow),
		MemberRegistryRoot: s.members.Root(),
		ForeignRoot:        s.foreignRoot(),
	}
	for i, slot := range s.sources {
		c.Sources[i] = SourceWires{ListId: big.NewInt(slot.listId), Registry: slot.registry}
	}
	for i := range c.Limits {
		c.Limits[i] = OutflowLimitWires{Asset: big.NewInt(0), Cap: big.NewInt(0), CosignAbove: big.NewInt(0)}
	}
	for i, row := range s.limits {
		c.Limits[i] = OutflowLimitWires{
			Asset:       row.asset,
			Cap:         new(big.Int).SetUint64(row.cap),
			CosignAbove: new(big.Int).SetUint64(row.cosign),
		}
	}
	c.LimitCount = len(s.limits)

	for i := range c.Inputs {
		c.Inputs[i] = zeroOpening()
	}
	for i, opening := range s.inputs {
		c.Inputs[i] = opening
	}
	c.NIn = len(s.inputs)

	for k, slot := range s.treeSlots(t) {
		c.TreeSlots[k] = shared.TreeSlot{ID: slot.ID, UtxoRoot: slot.UtxoRoot, NullifierRoot: slot.NullifierRoot}
	}
	for i := range c.Outputs {
		c.Outputs[i] = OutputWires{UtxoWires: zeroOpening(), CtHash: big.NewInt(0)}
	}
	for i, opening := range s.outputs {
		c.Outputs[i].UtxoWires = opening
		if i < len(s.ctHashes) && s.ctHashes[i] != nil {
			c.Outputs[i].CtHash = s.ctHashes[i]
		}
	}
	c.NOut = len(s.outputs)

	for i := range c.Subjects {
		c.Subjects[i], c.ForeignSubjects[i] = zeroMemberOpening(), zeroMemberOpening()
	}
	for _, rule := range s.rules {
		if rule.subject != SubjectAsset {
			continue
		}
		for o, output := range s.outputs {
			if spptest.AsBigInt(output.Domain).Int64() != protocol.UtxoDomain {
				continue
			}
			index := NInputs + NOutputs + o
			c.Subjects[index] = openingWires(s.members.Opening(spptest.AsBigInt(output.Asset)))
			if s.anyForeign() {
				c.ForeignSubjects[index] = openingWires(s.curator.Opening(spptest.AsBigInt(output.Asset)))
			}
		}
	}
	slots := append(append([]UtxoWires{}, c.Inputs[:]...), s.outputWires(c)...)
	for i, slot := range slots {
		c.Subjects[i], c.ForeignSubjects[i] = zeroMemberOpening(), zeroMemberOpening()
		if spptest.AsBigInt(slot.Domain).Int64() != protocol.UtxoDomain {
			continue
		}
		c.Subjects[i] = openingWires(s.members.Opening(spptest.AsBigInt(slot.OwnerPkHash)))
		if s.anyForeign() {
			c.ForeignSubjects[i] = openingWires(s.curator.Opening(spptest.AsBigInt(slot.OwnerPkHash)))
		}
	}

	// Padding rules repeat ring_policy::Rule::disabled.
	disabled := rule{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listAllow)}
	for k := range c.Rules {
		c.Rules[k] = disabled.packed()
	}
	for k, r := range s.rules {
		c.Rules[k] = r.packed()
	}
	c.PolicyLen = len(s.rules)

	for m := range c.InlineAssets {
		c.InlineAssets[m] = big.NewInt(0)
		c.InlineLimits[m] = big.NewInt(0)
	}
	for m, member := range s.inlineAssets {
		c.InlineAssets[m] = member
		if m < len(s.inlineLimits) {
			c.InlineLimits[m] = new(big.Int).SetUint64(s.inlineLimits[m])
		}
	}
	c.InlineCount = len(s.inlineAssets)
	return c
}

func (s *statement) outputWires(c *CustomRingPolicyCircuit) []UtxoWires {
	out := make([]UtxoWires, NOutputs)
	for i, output := range c.Outputs {
		out[i] = output.UtxoWires
	}
	return out
}

func (s *statement) foreignRoot() *big.Int {
	if s.anyForeign() {
		return s.curator.Root()
	}
	return big.NewInt(0)
}

// openingWires assigns a host opening, zero wires fill the branch not taken.
func openingWires(w spptest.MemberOpeningWitness) registry.MemberOpening {
	o := zeroMemberOpening()
	o.Index = new(big.Int).SetUint64(w.Index)
	for i := range w.Path {
		o.Path[i] = new(big.Int).Set(&w.Path[i])
	}
	if w.Present {
		o.Present, o.Next, o.Lists, o.EscrowKey = big.NewInt(1), w.Record.Next, w.Record.Lists, w.Record.EscrowKey
		return o
	}
	o.LowMember, o.LowNext, o.LowLists, o.LowEscrow = w.Record.Member, w.Record.Next, w.Record.Lists, w.Record.EscrowKey
	return o
}

func zeroMemberOpening() registry.MemberOpening {
	o := registry.MemberOpening{Present: big.NewInt(0), LowMember: big.NewInt(0), LowNext: big.NewInt(0), LowLists: big.NewInt(0), LowEscrow: big.NewInt(0)}
	o.Next, o.Lists, o.EscrowKey, o.Index = big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)
	for i := range o.Path {
		o.Path[i] = big.NewInt(0)
	}
	return o
}

func boolVar(value bool) *big.Int {
	if value {
		return big.NewInt(1)
	}
	return big.NewInt(0)
}

type hostPolicy struct {
	rules        []rule
	inlineAssets []*big.Int
	inlineLimits []uint64
	sources      [NSources]source
	limits       []limitRow
}

func (s *statement) policy() hostPolicy {
	return hostPolicy{
		rules:        s.rules,
		inlineAssets: s.inlineAssets,
		inlineLimits: s.inlineLimits,
		sources:      s.sources,
		limits:       s.limits,
	}
}

// Mirrors ring_policy::RuleTable::hash.
func (p hostPolicy) hash(t *testing.T) *big.Int {
	t.Helper()
	elements := []*big.Int{policyTableDomain, big.NewInt(PolicyVersion)}
	for _, slot := range p.sources {
		elements = append(elements, big.NewInt(slot.listId), slot.registry)
	}
	elements = append(elements, big.NewInt(int64(len(p.rules))))
	elements = append(elements, big.NewInt(int64(len(p.inlineAssets))))
	elements = append(elements, big.NewInt(int64(len(p.limits))))
	for _, r := range p.rules {
		elements = append(elements, r.packed())
	}
	for i, asset := range p.inlineAssets {
		limit := uint64(0)
		if i < len(p.inlineLimits) {
			limit = p.inlineLimits[i]
		}
		elements = append(elements, asset, new(big.Int).SetUint64(limit))
	}
	for _, row := range p.limits {
		elements = append(elements, row.asset, new(big.Int).SetUint64(row.cap), new(big.Int).SetUint64(row.cosign))
	}
	return spptest.MustHashChain(t, elements)
}

func hostUtxoHash(t *testing.T, w UtxoWires) *big.Int {
	t.Helper()
	return spptest.MustUtxoHash(t, protocol.Utxo{
		Domain:        spptest.AsBigInt(w.Domain),
		Owner:         spptest.MustOwnerHash(t, spptest.AsBigInt(w.OwnerPkHash), spptest.AsBigInt(w.NullifierPk)),
		Asset:         spptest.AsBigInt(w.Asset),
		Amount:        spptest.AsBigInt(w.Amount),
		Blinding:      spptest.AsBigInt(w.Blinding),
		DataHash:      spptest.AsBigInt(w.DataHash),
		RingDataHash:  spptest.AsBigInt(w.RingDataHash),
		RingProgramID: spptest.AsBigInt(w.RingProgramID),
	}, spptest.AsBigInt(w.TreeID))
}

// dummyOpening is a padding slot, everything zero except the blinding that
// keeps its hash indistinguishable from a real one.
func dummyOpening(t *testing.T, blinding int64) UtxoWires {
	t.Helper()
	opening := zeroOpening()
	opening.Domain = big.NewInt(protocol.DummyDomain)
	opening.Blinding = big.NewInt(blinding)
	return opening
}

func zeroOpening() UtxoWires {
	return UtxoWires{
		Domain:        big.NewInt(0),
		TreeID:        big.NewInt(0),
		OwnerPkHash:   big.NewInt(0),
		NullifierPk:   big.NewInt(0),
		Asset:         big.NewInt(0),
		Amount:        big.NewInt(0),
		Blinding:      big.NewInt(0),
		DataHash:      big.NewInt(0),
		RingDataHash:  big.NewInt(0),
		RingProgramID: big.NewInt(0),
	}
}

func fill(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

// pkField is the owner tag derivation both SPP and PolicyMember use.
func pkField(t *testing.T, key [32]byte) *big.Int {
	t.Helper()
	value, err := protocol.SolanaPkField(key)
	return spptest.MustHash(t, value, err)
}

// assetField is the untagged mint field, assets are not identities.
func assetField(t *testing.T, mint [32]byte) *big.Int {
	t.Helper()
	value, err := protocol.AssetField(mint)
	return spptest.MustHash(t, value, err)
}

func hex32(value *big.Int) string {
	return fmt.Sprintf("%x", feBytes(value))
}

func feBytes(value *big.Int) [32]byte {
	var out [32]byte
	value.FillBytes(out[:])
	return out
}
