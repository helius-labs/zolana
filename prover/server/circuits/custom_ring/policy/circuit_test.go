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

	"zolana/prover/circuits/custom_ring/base/audittest"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
)

// The host side of this test recomputes the whole statement outside the
// circuit, the audit block with crypto/ecdh and crypto/aes, the entry and
// policy hashing with the same iden3 Poseidon the Rust twins use, and the two
// SPP trees with the protocol helpers. Solving the compiled R1CS against that
// witness is the cross-check that the circuit computes what
// program-libs/ring-policy will recompute.

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
	// key
	// with Bsb22UnsupportedMultiCommitment.
	if len(commitments) != 1 {
		t.Fatalf("expected 1 BSB22 commitment, got %d", len(commitments))
	}
	if got := commitments[0].NbPublicCommitted; got != 0 {
		t.Fatalf("expected 0 public committed wires, got %d", got)
	}
	t.Logf("BSB22: 1 commitment over %d private wires", len(commitments[0].PrivateCommitted))
}

func TestConstants(t *testing.T) {
	solAsset := spptest.MustPoseidon(t, 3, []*big.Int{big.NewInt(0), big.NewInt(0)})
	if solAsset.Cmp(solAssetField) != 0 {
		t.Fatalf("Poseidon(0, 0) is %s, want the pinned SOL asset field %s", solAsset, solAssetField)
	}
	if emptyRingHash.Cmp(solAssetField) != 0 {
		t.Fatal("the empty ring hash must be the same Poseidon(0, 0) value")
	}

	for _, tag := range []string{addressDomainTag, recordDomainTag, tableDomainTag} {
		var padded [32]byte
		copy(padded[32-len(tag):], tag)
		if got := packedASCII(tag); got.Cmp(new(big.Int).SetBytes(padded[:])) != 0 {
			t.Fatalf("domain %q packs to %s", tag, got)
		}
	}
}

func TestCircuitSolvesValidWitness(t *testing.T) {
	cs := testConstraintSystem(t)

	solve(t, cs, validAssignment(t))
}

// A require-any group is satisfied when the subject is present in any one of
// the
// masked lists, the recipient sits on Allow within an Allow-or-Block group.
func TestCircuitSolvesGroupRule(t *testing.T) {
	cs := testConstraintSystem(t)

	f := defaultFixture()
	f.outputOwnerMask = listMask(listBlock, listAllow)
	solve(t, cs, buildAssignment(t, f))
}

// An any_of rule passes through either alternative, a recipient never added
// to Block through the absent branch, a recipient Active in both Approval and
// Block through the present branch.
func TestCircuitSolvesMixedModeRule(t *testing.T) {
	cs := testConstraintSystem(t)

	absent := mixedFixture()
	absent.listFacts = []int{senderNotFrozen, allowedNotBlocked}
	solve(t, cs, buildAssignment(t, absent))

	present := mixedFixture()
	present.recipient = approvedKey
	present.listFacts = []int{senderNotFrozen, approvedActive}
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
				c.RuleCountSelected[4] = big.NewInt(0)
				c.RuleCountSelected[3] = big.NewInt(1)
				return c
			},
		},
		{
			name: "entry mode swapped",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.ListFacts[0].Mode = big.NewInt(ModeAbsent)
				return c
			},
		},
		{
			name: "entry listId swapped",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.ListFacts[0].ListId = big.NewInt(listBlock)
				return c
			},
		},
		{
			name: "entry proves a different member",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.ListFacts[0].Member = new(big.Int).Add(spptest.AsBigInt(c.ListFacts[0].Member), big.NewInt(1))
				return c
			},
		},
		{
			name: "zero member",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.ListFacts[0].Member = big.NewInt(0)
				return c
			},
		},
		{
			name: "present member claimed absent",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.ListFacts[0].Mode = big.NewInt(ModeAbsent)
				c.ListFacts[0].AbsentBranch = big.NewInt(AbsentBranchUnclaimedAddress)
				return c
			},
		},
		{
			name: "cleared entry claimed present",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.ListFacts[2].Mode = big.NewInt(ModePresent)
				return c
			},
		},
		{
			name: "stale state root",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.StateRoot = new(big.Int).Add(spptest.AsBigInt(c.StateRoot), big.NewInt(1))
				return c
			},
		},
		{
			name: "entry inclusion proof does not open the state root",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.ListFacts[0].StatePathElements[0] = big.NewInt(1)
				return c
			},
		},
		{
			name: "entry absence proof does not open the nullifier root",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.ListFacts[1].NullifierLowPathElements[0] = big.NewInt(1)
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
			name: "curator slot repointed at the own owner",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.curatorSlotOwn = true
				return buildAssignment(t, f)
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
			name: "asset outside the inline allowlist",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.inlineAsset = fill(0xe5)
				return buildAssignment(t, f)
			},
		},
		{
			name: "input openings swapped",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				c := validAssignment(t)
				c.Inputs[0], c.Inputs[1] = c.Inputs[1], c.Inputs[0]
				return c
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
				c.OutputCountSelected[1] = big.NewInt(0)
				c.OutputCountSelected[0] = big.NewInt(1)
				return c
			},
		},
		{
			name: "tx scalar zero",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.keys = func(k audittest.Keys) audittest.Keys {
					return k.WithInfinityTxScalar(big.NewInt(0))
				}
				return buildAssignment(t, f)
			},
		},
		{
			name: "alt mask swapped with the primary mask",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				// Under the swapped wires the Approval absence
				// would cover, only
				// the packed row disagrees.
				f := mixedFixture()
				f.listFacts = []int{senderNotFrozen, allowedNotApproved}
				c := buildAssignment(t, f)
				c.Rules[0].ListMask, c.Rules[0].AltListMask = c.Rules[0].AltListMask, c.Rules[0].ListMask
				return c
			},
		},
		{
			name: "alt list fact in the primary mode",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := mixedFixture()
				f.recipient = approvedKey
				f.listFacts = []int{senderNotFrozen, approvedBlocked}
				return buildAssignment(t, f)
			},
		},
		{
			name: "primary-only list fact in the alt mode",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := mixedFixture()
				f.listFacts = []int{senderNotFrozen, allowedNotApproved}
				return buildAssignment(t, f)
			},
		},
		{
			name: "inline rule carrying an alt mask",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				f := defaultFixture()
				f.inlineAltMask = listMask(listBlock)
				return buildAssignment(t, f)
			},
		},
		{
			name: "rule mode outside present and absent",
			build: func(t *testing.T) *CustomRingPolicyCircuit {
				// The guard exempts the recipient, only the
				// mode assertion rejects.
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
	fmt.Printf("curator_owner_hash   %s\n", hex32(s.curatorOwnerHash))
	fmt.Printf("policy_hash          %s\n", hex32(s.policyHash))
	for i, name := range []string{"r1_allow_present", "r2_frozen_absent", "r3_block_cleared"} {
		d := s.derived[i]
		fmt.Printf("%s.seed      %s\n", name, hex32(d.seed))
		fmt.Printf("%s.address   %s\n", name, hex32(d.address))
		fmt.Printf("%s.data_hash %s\n", name, hex32(d.dataHash))
		fmt.Printf("%s.utxo_hash %s\n", name, hex32(d.utxoHash))
		fmt.Printf("%s.nullifier %s\n", name, hex32(d.nullifier))
	}
	fmt.Printf("state_root           %s\n", hex32(s.stateRoot))
	fmt.Printf("nullifier_root       %s\n", hex32(s.nullifierRoot))
	fmt.Printf("private_tx_hash      %s\n", hex32(s.privateTxHash))
	fmt.Printf("public_input_hash    %s\n", hex32(s.publicInputHash))

	fmt.Printf("empty_policy_hash    %s\n", hex32(hostPolicyHash(t, nil, nil, nil, emptySources())))
	oneMap := emptySources()
	oneMap[listAllow-1] = source{listId: listAllow, owner: s.ownOwnerHash}
	oneRule := []rule{{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listAllow)}}
	fmt.Printf("one_rule_policy_hash %s\n", hex32(hostPolicyHash(t, oneRule, nil, nil, oneMap)))
	twoMap := oneMap
	twoMap[listFrozen-1] = source{listId: listFrozen, owner: s.curatorOwnerHash}
	twoRules := append(oneRule, rule{subject: SubjectSender, mode: ModeAbsent, mask: listMask(listFrozen)})
	fmt.Printf("two_rule_policy_hash %s\n", hex32(hostPolicyHash(t, twoRules, nil, nil, twoMap)))
	mixedMap := emptySources()
	mixedMap[listBlock-1] = source{listId: listBlock, owner: s.ownOwnerHash}
	mixedMap[listApproval-1] = source{listId: listApproval, owner: s.ownOwnerHash}
	mixedRule := []rule{{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listApproval), altMask: listMask(listBlock)}}
	fmt.Printf("mixed_rule_policy_hash %s\n", hex32(hostPolicyHash(t, mixedRule, nil, nil, mixedMap)))
	perAssetRule := []rule{{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listAllow), guardTag: GuardAboveAmountByAsset}}
	fmt.Printf("per_asset_policy_hash %s\n", hex32(hostPolicyHash(
		t, perAssetRule, []*big.Int{pkField(t, fill(0xd4))}, []uint64{123}, oneMap,
	)))
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
	inlineAltMask     int64 // an alt mask on the inline asset rule
	recipient         [32]byte
	listFacts         []int // entry indices filling the list fact slots
	transferred       [32]byte
	inlineAsset       [32]byte
	secondTransferred [32]byte
	secondInlineAsset [32]byte
	perAssetLimits    []uint64
	rulesFree         bool
	dropCuratorSlot   bool
	curatorSlotOwn    bool
	keys              func(audittest.Keys) audittest.Keys
}

// Member keys of the fixture ring, the recipient knob picks among them.
var (
	allowedKey  = fill(0xa1)
	approvedKey = fill(0xf6)
)

// Indices into statement.entries, a member never added to a list has state 0
// and proves absence by its address alone.
const (
	allowedActive = iota
	senderNotFrozen
	blockedCleared
	allowedNotBlocked
	approvedActive
	approvedBlocked
	allowedNotApproved
)

func defaultFixture() fixture {
	return fixture{
		amount:      transferAmount,
		recipient:   allowedKey,
		listFacts:   []int{allowedActive, senderNotFrozen, blockedCleared},
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
	owner  *big.Int
}

func emptySources() [NSources]source {
	var out [NSources]source
	for i := range out {
		out[i] = source{listId: 0, owner: big.NewInt(0)}
	}
	return out
}

// entry is one host-side policy entry, mirroring ring_policy::ListEntry.
type entry struct {
	listId  int64
	member  *big.Int
	state   int64
	version int64
	content *big.Int
}

type derived struct {
	seed      *big.Int
	address   *big.Int
	dataHash  *big.Int
	utxoHash  *big.Int
	nullifier *big.Int
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

func (r rule) wires() RuleWires {
	return RuleWires{
		Packed:      r.packed(),
		Subject:     big.NewInt(r.subject),
		Mode:        big.NewInt(r.mode),
		ListMask:    big.NewInt(r.mask),
		AltListMask: big.NewInt(r.altMask),
		GuardTag:    big.NewInt(r.guardTag),
		Threshold:   new(big.Int).SetUint64(r.threshold),
	}
}

type statement struct {
	ownOwnerHash     *big.Int
	curatorOwnerHash *big.Int
	sources          [NSources]source
	rules            []rule
	inlineAssets     []*big.Int
	inlineLimits     []uint64
	policyHash       *big.Int

	entries []entry
	derived []derived

	stateRoot     *big.Int
	nullifierRoot *big.Int
	stateLeaf     map[int]uint64
	stateProofs   map[uint64]protocol.StateTreeWitness
	nonInclusion  []protocol.NonInclusionWitness

	inputs  []UtxoWires
	outputs []UtxoWires

	addressChain     *big.Int
	externalDataHash *big.Int
	privateTxHash    *big.Int
	publicInputHash  *big.Int

	keys audittest.Keys
}

// newStatement builds a ring whose entries allow the recipient, hold no Frozen
// entry for the sender, carry a cleared Block entry and list a second recipient
// as Active in both Approval and Block, a policy demanding the first three plus
// a guarded Approval rule, and a two-in two-out transaction that satisfies
// them. The Frozen list is sourced from a curator's entries, every other list
// from the ring's own.
func newStatement(t *testing.T, f fixture) *statement {
	t.Helper()
	s := &statement{}

	s.ownOwnerHash = spptest.MustOwnerHash(t,
		pkField(t, fill(0x11)),
		spptest.MustNullifierPk(t, big.NewInt(0)),
	)
	s.curatorOwnerHash = spptest.MustOwnerHash(t,
		pkField(t, fill(0x12)),
		spptest.MustNullifierPk(t, big.NewInt(0)),
	)
	s.sources = emptySources()
	for _, listId := range []int64{listAllow, listBlock, listApproval} {
		s.sources[listId-1] = source{listId: listId, owner: s.ownOwnerHash}
	}
	s.sources[listFrozen-1] = source{listId: listFrozen, owner: s.curatorOwnerHash}

	allowed := pkField(t, allowedKey)
	sender := pkField(t, fill(0xb2))
	blocked := pkField(t, fill(0xc3))
	approved := pkField(t, approvedKey)
	asset := pkField(t, f.transferred)

	s.entries = []entry{
		allowedActive:      {listId: listAllow, member: allowed, state: EntryStateActive, version: 0, content: big.NewInt(0)},
		senderNotFrozen:    {listId: listFrozen, member: sender, state: 0, version: 0, content: big.NewInt(0)},
		blockedCleared:     {listId: listBlock, member: blocked, state: EntryStateCleared, version: 1, content: big.NewInt(0)},
		allowedNotBlocked:  {listId: listBlock, member: allowed, state: 0, version: 0, content: big.NewInt(0)},
		approvedActive:     {listId: listApproval, member: approved, state: EntryStateActive, version: 0, content: big.NewInt(0)},
		approvedBlocked:    {listId: listBlock, member: approved, state: EntryStateActive, version: 0, content: big.NewInt(0)},
		allowedNotApproved: {listId: listApproval, member: allowed, state: 0, version: 0, content: big.NewInt(0)},
	}
	for _, r := range s.entries {
		s.derived = append(s.derived, deriveRecord(t, s.sources[r.listId-1].owner, r))
	}
	// The knobs repoint the map after derivation, leaving the entry
	// fixtures
	// under the curator.
	if f.dropCuratorSlot {
		s.sources[listFrozen-1] = source{listId: 0, owner: big.NewInt(0)}
	}
	if f.curatorSlotOwn {
		s.sources[listFrozen-1].owner = s.ownOwnerHash
	}

	s.rules = []rule{
		{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listAllow)},
		{subject: SubjectSender, mode: ModeAbsent, mask: listMask(listFrozen)},
		{subject: SubjectAsset, mode: ModePresent, mask: listMask()},
		{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listApproval), guardTag: GuardAboveAmount, threshold: guardThreshold},
	}
	s.inlineAssets = []*big.Int{pkField(t, f.inlineAsset)}
	if f.secondInlineAsset != [32]byte{} {
		s.inlineAssets = append(s.inlineAssets, pkField(t, f.secondInlineAsset))
	}
	if f.perAssetLimits != nil {
		s.rules[3].guardTag = GuardAboveAmountByAsset
		s.rules[3].threshold = 0
		s.inlineLimits = f.perAssetLimits
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
	s.policyHash = hostPolicyHash(t, s.rules, s.inlineAssets, s.inlineLimits, s.sources)

	s.keys = audittest.DefaultKeys(t)
	if f.keys != nil {
		s.keys = f.keys(s.keys)
	}
	s.buildTrees(t)
	secondAsset := asset
	if f.secondTransferred != [32]byte{} {
		secondAsset = pkField(t, f.secondTransferred)
	}
	s.buildTransaction(t, pkField(t, f.recipient), sender, asset, secondAsset, f.amount, f.secondAmount)
	return s
}

// buildTrees seeds the SPP roots the entry proofs open against, the created
// entries as state tree leaves and their addresses as spent nullifiers.
func (s *statement) buildTrees(t *testing.T) {
	t.Helper()
	leaves := map[uint64]*big.Int{}
	tree := spptest.MustNewNullifierTree(t)
	s.stateLeaf = map[int]uint64{}
	s.nonInclusion = nil
	for i, r := range s.entries {
		if r.state == 0 {
			continue
		}
		s.stateLeaf[i] = uint64(len(leaves))
		leaves[s.stateLeaf[i]] = s.derived[i].utxoHash
		if err := tree.Insert(s.derived[i].address); err != nil {
			t.Fatalf("insert entry address: %v", err)
		}
	}
	s.stateRoot, s.stateProofs = spptest.MustBuildSparseStateTree(t, leaves)
	s.nullifierRoot = tree.Root()
	// A created entry is unspent, a never created one has no address.
	for i, r := range s.entries {
		target := s.derived[i].nullifier
		if r.state == 0 {
			target = s.derived[i].address
		}
		s.nonInclusion = append(s.nonInclusion, spptest.MustNonInclusion(t, tree, target))
	}
}

func (s *statement) buildTransaction(
	t *testing.T,
	recipient, sender, asset, secondAsset *big.Int,
	amount, secondAmount uint64,
) {
	t.Helper()
	spent := UtxoWires{
		Domain:        big.NewInt(protocol.UtxoDomain),
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
		OwnerPkHash:   recipient,
		NullifierPk:   spptest.MustNullifierPk(t, big.NewInt(9)),
		Asset:         asset,
		Amount:        new(big.Int).SetUint64(amount),
		Blinding:      big.NewInt(0x52),
		DataHash:      big.NewInt(0),
		RingDataHash:  big.NewInt(0),
		RingProgramID: big.NewInt(0),
	}
	s.inputs = []UtxoWires{spent, dummyOpening(t, 0x53)}
	// A second real output to the same recipient exercises the
	// per-recipient
	// amount aggregation, else a dummy fills the slot.
	second := dummyOpening(t, 0x54)
	if secondAmount > 0 {
		second = UtxoWires{
			Domain:        big.NewInt(protocol.UtxoDomain),
			OwnerPkHash:   recipient,
			NullifierPk:   spptest.MustNullifierPk(t, big.NewInt(11)),
			Asset:         secondAsset,
			Amount:        new(big.Int).SetUint64(secondAmount),
			Blinding:      big.NewInt(0x55),
			DataHash:      big.NewInt(0),
			RingDataHash:  big.NewInt(0),
			RingProgramID: big.NewInt(0),
		}
	}
	s.outputs = []UtxoWires{created, second}

	s.addressChain = spptest.MustHashChain(t, []*big.Int{big.NewInt(0), big.NewInt(0)})
	s.externalDataHash = big.NewInt(0x5eed)
	s.updateHashes(t)
}

func buildAssignment(t *testing.T, f fixture) *CustomRingPolicyCircuit {
	t.Helper()
	s := newStatement(t, f)
	if f.rulesFree {
		return s.assignment(t, nil)
	}
	return s.assignment(t, f.listFacts)
}

func (s *statement) assignment(t *testing.T, listFacts []int) *CustomRingPolicyCircuit {
	t.Helper()
	s.updateHashes(t)
	wires := s.keys.AuditBlockWires(s.privateTxHash)
	c := &CustomRingPolicyCircuit{
		PublicInputHash:  s.publicInputHash,
		PrivateTxHash:    wires.PrivateTxHash,
		TxViewingSk:      wires.TxViewingSk,
		EphSk:            wires.EphSk,
		AuditorPk:        wires.AuditorPk,
		AddressChain:     s.addressChain,
		ExternalDataHash: s.externalDataHash,
		StateRoot:        s.stateRoot,
		NullifierRoot:    s.nullifierRoot,
	}
	for i, slot := range s.sources {
		c.Sources[i] = SourceWires{ListId: big.NewInt(slot.listId), OwnerHash: slot.owner}
	}

	for i := range c.Inputs {
		c.Inputs[i] = zeroOpening()
		c.InputCountSelected[i] = big.NewInt(0)
	}
	for i, opening := range s.inputs {
		c.Inputs[i] = opening
	}
	c.InputCountSelected[len(s.inputs)-1] = big.NewInt(1)

	for i := range c.Outputs {
		c.Outputs[i] = zeroOpening()
		c.OutputCountSelected[i] = big.NewInt(0)
	}
	for i, opening := range s.outputs {
		c.Outputs[i] = opening
	}
	c.OutputCountSelected[len(s.outputs)-1] = big.NewInt(1)

	// Padding rules repeat ring_policy::Rule::disabled.
	disabled := rule{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listAllow)}
	for k := range c.Rules {
		c.Rules[k] = disabled.wires()
		c.RuleCountSelected[k] = big.NewInt(0)
	}
	for k, r := range s.rules {
		c.Rules[k] = r.wires()
	}
	c.RuleCountSelected[NRules] = big.NewInt(0)
	c.RuleCountSelected[len(s.rules)] = big.NewInt(1)

	for m := range c.InlineAssets {
		c.InlineAssets[m] = big.NewInt(0)
		c.InlineLimits[m] = big.NewInt(0)
		c.InlineAssetCountSelected[m] = big.NewInt(0)
	}
	for m, member := range s.inlineAssets {
		c.InlineAssets[m] = member
		if m < len(s.inlineLimits) {
			c.InlineLimits[m] = new(big.Int).SetUint64(s.inlineLimits[m])
		}
	}
	c.InlineAssetCountSelected[NInlineAssets] = big.NewInt(0)
	c.InlineAssetCountSelected[len(s.inlineAssets)] = big.NewInt(1)

	for e := range c.ListFacts {
		c.ListFacts[e] = disabledListFact()
	}
	for e, index := range listFacts {
		c.ListFacts[e] = s.listFactForEntry(t, index)
	}
	return c
}

func (s *statement) listFactForEntry(t *testing.T, index int) ListFactWires {
	t.Helper()
	entry := s.entries[index]
	mode, branch := int64(ModePresent), int64(0)
	switch entry.state {
	case 0:
		mode, branch = ModeAbsent, AbsentBranchUnclaimedAddress
	case EntryStateCleared:
		mode, branch = ModeAbsent, AbsentBranchCleared
	}
	fact := ListFactWires{
		Enabled:               big.NewInt(1),
		Mode:                  big.NewInt(mode),
		ListId:                big.NewInt(entry.listId),
		Member:                entry.member,
		ContentHash:           entry.content,
		Version:               big.NewInt(entry.version),
		State:                 big.NewInt(entry.state),
		AbsentBranch:          big.NewInt(branch),
		NullifierLowPathIndex: big.NewInt(0),
		StatePathIndex:        big.NewInt(0),
	}
	for i := range fact.NullifierLowPathElements {
		fact.NullifierLowPathElements[i] = big.NewInt(0)
	}
	for i := range fact.StatePathElements {
		fact.StatePathElements[i] = big.NewInt(0)
	}

	witness := s.nonInclusion[index]
	fact.NullifierLowValue = witness.LowValue
	fact.NullifierNextValue = witness.NextValue
	fact.NullifierLowPathIndex = new(big.Int).SetUint64(witness.LowIndex)
	for i, element := range witness.PathElements {
		fact.NullifierLowPathElements[i] = element
	}

	if entry.state == 0 {
		return fact
	}
	proof, ok := s.stateProofs[s.stateLeaf[index]]
	if !ok {
		t.Fatalf("missing state proof for entry %d", index)
	}
	fact.StatePathIndex = new(big.Int).SetUint64(proof.PathIndex)
	for i, element := range proof.PathElements {
		fact.StatePathElements[i] = element
	}
	return fact
}

// deriveRecord mirrors ring_policy::entry, the seed and address fixed by
// (listId, member) while the commitment moves with the state and version.
func deriveRecord(t *testing.T, ownerHash *big.Int, r entry) derived {
	t.Helper()
	seed := spptest.MustPoseidon(t, 4, []*big.Int{policyAddressDomain, big.NewInt(r.listId), r.member})
	addressUtxoHash := spptest.MustPoseidon(t, 7, []*big.Int{
		big.NewInt(protocol.AddressDomain),
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		emptyRingHash,
		spptest.MustPoseidon(t, 3, []*big.Int{ownerHash, seed}),
	})
	address := spptest.MustPoseidon(t, 4, []*big.Int{addressUtxoHash, seed, big.NewInt(0)})
	dataHash := spptest.MustPoseidon(t, 8, []*big.Int{
		policyRecordDomain,
		address,
		big.NewInt(r.listId),
		r.member,
		big.NewInt(r.state),
		big.NewInt(r.version),
		r.content,
	})
	utxoHash := spptest.MustPoseidon(t, 7, []*big.Int{
		big.NewInt(protocol.UtxoDomain),
		solAssetField,
		big.NewInt(0),
		dataHash,
		emptyRingHash,
		spptest.MustPoseidon(t, 3, []*big.Int{ownerHash, big.NewInt(r.version)}),
	})
	return derived{
		seed:      seed,
		address:   address,
		dataHash:  dataHash,
		utxoHash:  utxoHash,
		nullifier: spptest.MustPoseidon(t, 4, []*big.Int{utxoHash, big.NewInt(r.version), big.NewInt(0)}),
	}
}

// hostPolicyHash mirrors ring_policy::RuleTable::hash.
func hostPolicyHash(
	t *testing.T,
	rules []rule,
	inlineAssets []*big.Int,
	inlineLimits []uint64,
	sources [NSources]source,
) *big.Int {
	t.Helper()
	elements := []*big.Int{policyTableDomain, big.NewInt(PolicyVersion)}
	for _, slot := range sources {
		elements = append(elements, big.NewInt(slot.listId), slot.owner)
	}
	elements = append(elements, big.NewInt(int64(len(rules))))
	for _, r := range rules {
		elements = append(elements, r.packed())
	}
	for i, asset := range inlineAssets {
		limit := uint64(0)
		if i < len(inlineLimits) {
			limit = inlineLimits[i]
		}
		elements = append(elements, asset, new(big.Int).SetUint64(limit))
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
	})
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

func disabledListFact() ListFactWires {
	fact := ListFactWires{
		Enabled:               big.NewInt(0),
		Mode:                  big.NewInt(0),
		ListId:                big.NewInt(0),
		Member:                big.NewInt(0),
		ContentHash:           big.NewInt(0),
		Version:               big.NewInt(0),
		State:                 big.NewInt(0),
		AbsentBranch:          big.NewInt(0),
		NullifierLowValue:     big.NewInt(0),
		NullifierNextValue:    big.NewInt(0),
		NullifierLowPathIndex: big.NewInt(0),
		StatePathIndex:        big.NewInt(0),
	}
	for i := range fact.NullifierLowPathElements {
		fact.NullifierLowPathElements[i] = big.NewInt(0)
	}
	for i := range fact.StatePathElements {
		fact.StatePathElements[i] = big.NewInt(0)
	}
	return fact
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

func hex32(value *big.Int) string {
	return fmt.Sprintf("%x", feBytes(value))
}

func feBytes(value *big.Int) [32]byte {
	var out [32]byte
	value.FillBytes(out[:])
	return out
}
