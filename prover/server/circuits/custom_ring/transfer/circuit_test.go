package transfer

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

	"zolana/prover/circuits/custom_ring/audittest"
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
	kindAllow    = 1
	kindBlock    = 2
	kindFrozen   = 3
	kindApproval = 7

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
			&Circuit{},
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
	// private wires, a committed public wire makes the vk parser reject the key
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

// A require-any group is satisfied when the subject is present in any one of the
// masked lists, the recipient sits on Allow within an Allow-or-Block group.
func TestCircuitSolvesGroupRule(t *testing.T) {
	cs := testConstraintSystem(t)

	f := defaultFixture()
	f.outputOwnerMask = lmask(kindBlock, kindAllow)
	solve(t, cs, buildAssignment(t, f))
}

// An any_of rule passes through either alternative, a recipient never added
// to Block through the absent branch, a recipient Active in both Approval and
// Block through the present branch.
func TestCircuitSolvesMixedModeRule(t *testing.T) {
	cs := testConstraintSystem(t)

	absent := mixedFixture()
	absent.answers = []int{senderNotFrozen, allowedNotBlocked}
	solve(t, cs, buildAssignment(t, absent))

	present := mixedFixture()
	present.recipient = approvedKey
	present.answers = []int{senderNotFrozen, approvedActive}
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
		build func(*testing.T) *Circuit
	}{
		{
			name: "rule dropped from the table",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.LenOneHot[4] = big.NewInt(0)
				c.LenOneHot[3] = big.NewInt(1)
				return c
			},
		},
		{
			name: "entry mode swapped",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Answers[0].Mode = big.NewInt(ModeAbsent)
				return c
			},
		},
		{
			name: "entry listId swapped",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Answers[0].ListId = big.NewInt(kindBlock)
				return c
			},
		},
		{
			name: "entry proves a different member",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Answers[0].Member = new(big.Int).Add(spptest.AsBigInt(c.Answers[0].Member), big.NewInt(1))
				return c
			},
		},
		{
			name: "zero member",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Answers[0].Member = big.NewInt(0)
				return c
			},
		},
		{
			name: "present member claimed absent",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Answers[0].Mode = big.NewInt(ModeAbsent)
				c.Answers[0].AbsentBranch = big.NewInt(AbsentBranchNoAddress)
				return c
			},
		},
		{
			name: "cleared entry claimed present",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Answers[2].Mode = big.NewInt(ModePresent)
				return c
			},
		},
		{
			name: "stale state root",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.StateRoot = new(big.Int).Add(spptest.AsBigInt(c.StateRoot), big.NewInt(1))
				return c
			},
		},
		{
			name: "entry inclusion proof does not open the state root",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Answers[0].StatePathElements[0] = big.NewInt(1)
				return c
			},
		},
		{
			name: "entry absence proof does not open the nullifier root",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Answers[1].NfPathElements[0] = big.NewInt(1)
				return c
			},
		},
		{
			name: "curator slot dropped from the map",
			build: func(t *testing.T) *Circuit {
				f := defaultFixture()
				f.dropCuratorSlot = true
				return buildAssignment(t, f)
			},
		},
		{
			name: "live source slots swapped in the witness",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Sources[kindAllow-1], c.Sources[kindFrozen-1] =
					c.Sources[kindFrozen-1], c.Sources[kindAllow-1]
				return c
			},
		},
		{
			name: "curator slot repointed at the own owner",
			build: func(t *testing.T) *Circuit {
				f := defaultFixture()
				f.curatorSlotOwn = true
				return buildAssignment(t, f)
			},
		},
		{
			name: "live listId duplicated into a second slot in the witness",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Sources[4] = c.Sources[kindFrozen-1]
				return c
			},
		},
		{
			name: "guard bypassed above the threshold",
			build: func(t *testing.T) *Circuit {
				f := defaultFixture()
				f.amount = guardThreshold + 1
				return buildAssignment(t, f)
			},
		},
		{
			name: "guard bypassed by structuring below the threshold",
			build: func(t *testing.T) *Circuit {
				f := defaultFixture()
				f.amount = guardThreshold - 500
				f.secondAmount = guardThreshold - 500
				return buildAssignment(t, f)
			},
		},
		{
			name: "output owner group excludes the recipient's list",
			build: func(t *testing.T) *Circuit {
				f := defaultFixture()
				f.outputOwnerMask = lmask(kindBlock, kindApproval)
				return buildAssignment(t, f)
			},
		},
		{
			name: "asset outside the inline allowlist",
			build: func(t *testing.T) *Circuit {
				f := defaultFixture()
				f.inlineAsset = fill(0xe5)
				return buildAssignment(t, f)
			},
		},
		{
			name: "input openings swapped",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Inputs[0], c.Inputs[1] = c.Inputs[1], c.Inputs[0]
				return c
			},
		},
		{
			name: "dummy input reclassified as a utxo",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Inputs[1].Domain = big.NewInt(protocol.UtxoDomain)
				return c
			},
		},
		{
			name: "output count understated",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.NOutOneHot[1] = big.NewInt(0)
				c.NOutOneHot[0] = big.NewInt(1)
				return c
			},
		},
		{
			name: "tx scalar zero",
			build: func(t *testing.T) *Circuit {
				f := defaultFixture()
				f.keys = func(k audittest.Keys) audittest.Keys {
					return k.WithInfinityTxScalar(big.NewInt(0))
				}
				return buildAssignment(t, f)
			},
		},
		{
			name: "alt mask swapped with the primary mask",
			build: func(t *testing.T) *Circuit {
				// Under the swapped wires the Approval absence would cover, only
				// the packed row disagrees.
				f := mixedFixture()
				f.answers = []int{senderNotFrozen, allowedNotApproved}
				c := buildAssignment(t, f)
				c.Rules[0].Mask, c.Rules[0].AltMask = c.Rules[0].AltMask, c.Rules[0].Mask
				return c
			},
		},
		{
			name: "alt list answered in the primary mode",
			build: func(t *testing.T) *Circuit {
				f := mixedFixture()
				f.recipient = approvedKey
				f.answers = []int{senderNotFrozen, approvedBlocked}
				return buildAssignment(t, f)
			},
		},
		{
			name: "primary-only list answered in the alt mode",
			build: func(t *testing.T) *Circuit {
				f := mixedFixture()
				f.answers = []int{senderNotFrozen, allowedNotApproved}
				return buildAssignment(t, f)
			},
		},
		{
			name: "inline rule carrying an alt mask",
			build: func(t *testing.T) *Circuit {
				f := defaultFixture()
				f.inlineAltMask = lmask(kindBlock)
				return buildAssignment(t, f)
			},
		},
		{
			name: "rule mode outside present and absent",
			build: func(t *testing.T) *Circuit {
				// The guard exempts the recipient, only the mode assertion rejects.
				f := defaultFixture()
				f.guardedMode = 3
				return buildAssignment(t, f)
			},
		},
		{
			name: "alt mask bit past the eighth list",
			build: func(t *testing.T) *Circuit {
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

	fmt.Printf("empty_policy_hash    %s\n", hex32(hostPolicyHash(t, nil, nil, emptySources())))
	oneMap := emptySources()
	oneMap[kindAllow-1] = source{listId: kindAllow, owner: s.ownOwnerHash}
	oneRule := []rule{{subject: SubjectOutputOwner, mode: ModePresent, mask: lmask(kindAllow)}}
	fmt.Printf("one_rule_policy_hash %s\n", hex32(hostPolicyHash(t, oneRule, nil, oneMap)))
	twoMap := oneMap
	twoMap[kindFrozen-1] = source{listId: kindFrozen, owner: s.curatorOwnerHash}
	twoRules := append(oneRule, rule{subject: SubjectSender, mode: ModeAbsent, mask: lmask(kindFrozen)})
	fmt.Printf("two_rule_policy_hash %s\n", hex32(hostPolicyHash(t, twoRules, nil, twoMap)))
	mixedMap := emptySources()
	mixedMap[kindBlock-1] = source{listId: kindBlock, owner: s.ownOwnerHash}
	mixedMap[kindApproval-1] = source{listId: kindApproval, owner: s.ownOwnerHash}
	mixedRule := []rule{{subject: SubjectOutputOwner, mode: ModePresent, mask: lmask(kindApproval), altMask: lmask(kindBlock)}}
	fmt.Printf("mixed_rule_policy_hash %s\n", hex32(hostPolicyHash(t, mixedRule, nil, mixedMap)))
}

func solve(t *testing.T, cs constraint.ConstraintSystem, assignment *Circuit) {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	if err := cs.IsSolved(witness); err != nil {
		t.Fatalf("solve: %v", err)
	}
}

func validAssignment(t *testing.T) *Circuit {
	t.Helper()
	return buildAssignment(t, defaultFixture())
}

// fixture is the knob set of one statement, a tamper row needing a
// self-consistent witness rebuilds with one knob changed.
type fixture struct {
	amount             uint64
	secondAmount       uint64 // 0 keeps one real output, else a second to the same recipient
	outputOwnerMask    int64  // 0 keeps the single Allow rule, else the OutputOwner rule's list mask
	outputOwnerAltMask int64  // lists satisfying the OutputOwner rule in the opposite mode
	guardedMode        int64  // 0 keeps Present, else the guarded Approval rule's mode
	inlineAltMask      int64  // an alt mask on the inline asset rule
	recipient          [32]byte
	answers            []int // entry indices filling the answer slots
	transferred        [32]byte
	inlineAsset        [32]byte
	rulesFree          bool
	dropCuratorSlot    bool
	curatorSlotOwn     bool
	keys               func(audittest.Keys) audittest.Keys
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
		answers:     []int{allowedActive, senderNotFrozen, blockedCleared},
		transferred: fill(0xd4),
		inlineAsset: fill(0xd4),
	}
}

// mixedFixture swaps the Allow rule for any_of(OutputOwner, present Approval,
// absent Block).
func mixedFixture() fixture {
	f := defaultFixture()
	f.outputOwnerMask = lmask(kindApproval)
	f.outputOwnerAltMask = lmask(kindBlock)
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

// lmask ORs the bit of each list id, mirroring ring_policy::ListSet::of.
func lmask(ids ...int64) int64 {
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
		Packed:    r.packed(),
		Subject:   big.NewInt(r.subject),
		Mode:      big.NewInt(r.mode),
		Mask:      big.NewInt(r.mask),
		AltMask:   big.NewInt(r.altMask),
		GuardTag:  big.NewInt(r.guardTag),
		Threshold: new(big.Int).SetUint64(r.threshold),
	}
}

type statement struct {
	ownOwnerHash     *big.Int
	curatorOwnerHash *big.Int
	sources          [NSources]source
	rules            []rule
	inlineAssets     []*big.Int
	policyHash       *big.Int

	entries []entry
	derived []derived

	stateRoot     *big.Int
	nullifierRoot *big.Int
	stateLeaf     map[int]uint64
	stateProofs   map[uint64]protocol.StateTreeWitness
	nonInclusion  []protocol.NonInclusionWitness

	inputs  []OpeningWires
	outputs []OpeningWires

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
	for _, listId := range []int64{kindAllow, kindBlock, kindApproval} {
		s.sources[listId-1] = source{listId: listId, owner: s.ownOwnerHash}
	}
	s.sources[kindFrozen-1] = source{listId: kindFrozen, owner: s.curatorOwnerHash}

	allowed := pkField(t, allowedKey)
	sender := pkField(t, fill(0xb2))
	blocked := pkField(t, fill(0xc3))
	approved := pkField(t, approvedKey)
	asset := pkField(t, f.transferred)

	s.entries = []entry{
		allowedActive:      {listId: kindAllow, member: allowed, state: EntryStateActive, version: 0, content: big.NewInt(0)},
		senderNotFrozen:    {listId: kindFrozen, member: sender, state: 0, version: 0, content: big.NewInt(0)},
		blockedCleared:     {listId: kindBlock, member: blocked, state: EntryStateCleared, version: 1, content: big.NewInt(0)},
		allowedNotBlocked:  {listId: kindBlock, member: allowed, state: 0, version: 0, content: big.NewInt(0)},
		approvedActive:     {listId: kindApproval, member: approved, state: EntryStateActive, version: 0, content: big.NewInt(0)},
		approvedBlocked:    {listId: kindBlock, member: approved, state: EntryStateActive, version: 0, content: big.NewInt(0)},
		allowedNotApproved: {listId: kindApproval, member: allowed, state: 0, version: 0, content: big.NewInt(0)},
	}
	for _, r := range s.entries {
		s.derived = append(s.derived, deriveRecord(t, s.sources[r.listId-1].owner, r))
	}
	// The knobs repoint the map after derivation, leaving the entry fixtures
	// under the curator.
	if f.dropCuratorSlot {
		s.sources[kindFrozen-1] = source{listId: 0, owner: big.NewInt(0)}
	}
	if f.curatorSlotOwn {
		s.sources[kindFrozen-1].owner = s.ownOwnerHash
	}

	s.rules = []rule{
		{subject: SubjectOutputOwner, mode: ModePresent, mask: lmask(kindAllow)},
		{subject: SubjectSender, mode: ModeAbsent, mask: lmask(kindFrozen)},
		{subject: SubjectAsset, mode: ModePresent, mask: lmask()},
		{subject: SubjectOutputOwner, mode: ModePresent, mask: lmask(kindApproval), guardTag: GuardAboveAmount, threshold: guardThreshold},
	}
	s.inlineAssets = []*big.Int{pkField(t, f.inlineAsset)}
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
	s.policyHash = hostPolicyHash(t, s.rules, s.inlineAssets, s.sources)

	s.keys = audittest.DefaultKeys(t)
	if f.keys != nil {
		s.keys = f.keys(s.keys)
	}
	s.buildTrees(t)
	s.buildTransaction(t, pkField(t, f.recipient), sender, asset, f.amount, f.secondAmount)
	return s
}

// buildTrees seeds the SPP roots the entry proofs open against, the created
// entries as state tree leaves and their addresses as spent nullifiers.
func (s *statement) buildTrees(t *testing.T) {
	t.Helper()
	leaves := map[uint64]*big.Int{}
	tree := spptest.MustNewNullifierTree(t)
	s.stateLeaf = map[int]uint64{}
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

func (s *statement) buildTransaction(t *testing.T, recipient, sender, asset *big.Int, amount, secondAmount uint64) {
	t.Helper()
	spent := OpeningWires{
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
	created := OpeningWires{
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
	s.inputs = []OpeningWires{spent, dummyOpening(t, 0x53)}
	// A second real output to the same recipient exercises the per-recipient
	// amount aggregation, else a dummy fills the slot.
	second := dummyOpening(t, 0x54)
	if secondAmount > 0 {
		second = OpeningWires{
			Domain:        big.NewInt(protocol.UtxoDomain),
			OwnerPkHash:   recipient,
			NullifierPk:   spptest.MustNullifierPk(t, big.NewInt(11)),
			Asset:         asset,
			Amount:        new(big.Int).SetUint64(secondAmount),
			Blinding:      big.NewInt(0x55),
			DataHash:      big.NewInt(0),
			RingDataHash:  big.NewInt(0),
			RingProgramID: big.NewInt(0),
		}
	}
	s.outputs = []OpeningWires{created, second}

	// A dummy slot contributes 0 to the chain, mirroring the circuit's isUtxo mux.
	secondContribution := big.NewInt(0)
	if secondAmount > 0 {
		secondContribution = hostUtxoHash(t, s.outputs[1])
	}
	s.addressChain = spptest.MustHashChain(t, []*big.Int{big.NewInt(0), big.NewInt(0)})
	s.externalDataHash = big.NewInt(0x5eed)
	s.privateTxHash = spptest.MustPrivateTxHash(t,
		[]*big.Int{hostUtxoHash(t, s.inputs[0]), big.NewInt(0)},
		[]*big.Int{hostUtxoHash(t, s.outputs[0]), secondContribution},
		[]*big.Int{big.NewInt(0), big.NewInt(0)},
		s.externalDataHash,
	)

	elements := s.keys.ChainElements(t, s.privateTxHash)
	s.publicInputHash = spptest.MustHashChain(t, append(elements,
		s.policyHash, s.stateRoot, s.nullifierRoot))
}

func buildAssignment(t *testing.T, f fixture) *Circuit {
	t.Helper()
	s := newStatement(t, f)

	wires := s.keys.BlockWires(s.privateTxHash)
	c := &Circuit{
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
		c.NInOneHot[i] = big.NewInt(0)
	}
	for i, opening := range s.inputs {
		c.Inputs[i] = opening
	}
	c.NInOneHot[len(s.inputs)-1] = big.NewInt(1)

	for i := range c.Outputs {
		c.Outputs[i] = zeroOpening()
		c.NOutOneHot[i] = big.NewInt(0)
	}
	for i, opening := range s.outputs {
		c.Outputs[i] = opening
	}
	c.NOutOneHot[len(s.outputs)-1] = big.NewInt(1)

	// Padding rules repeat ring_policy::Rule::disabled.
	disabled := rule{subject: SubjectOutputOwner, mode: ModePresent, mask: lmask(kindAllow)}
	for k := range c.Rules {
		c.Rules[k] = disabled.wires()
		c.LenOneHot[k] = big.NewInt(0)
	}
	for k, r := range s.rules {
		c.Rules[k] = r.wires()
	}
	c.LenOneHot[NRules] = big.NewInt(0)
	c.LenOneHot[len(s.rules)] = big.NewInt(1)

	for m := range c.InlineAssets {
		c.InlineAssets[m] = big.NewInt(0)
		c.InlineCountOneHot[m] = big.NewInt(0)
	}
	for m, member := range s.inlineAssets {
		c.InlineAssets[m] = member
	}
	c.InlineCountOneHot[NInlineAssets] = big.NewInt(0)
	c.InlineCountOneHot[len(s.inlineAssets)] = big.NewInt(1)

	for e := range c.Answers {
		c.Answers[e] = zeroPoolEntry()
	}
	if f.rulesFree {
		return c
	}
	for e, index := range f.answers {
		c.Answers[e] = s.poolEntry(t, index)
	}
	return c
}

// poolEntry answers with the entry's own fact, an Active entry present, a
// cleared or never added one absent.
func (s *statement) poolEntry(t *testing.T, index int) RuleAnswerWires {
	t.Helper()
	r := s.entries[index]
	mode, branch := int64(ModePresent), int64(0)
	switch r.state {
	case 0:
		mode, branch = ModeAbsent, AbsentBranchNoAddress
	case EntryStateCleared:
		mode, branch = ModeAbsent, AbsentBranchCleared
	}
	entry := RuleAnswerWires{
		Enabled:        big.NewInt(1),
		Mode:           big.NewInt(mode),
		ListId:         big.NewInt(r.listId),
		Member:         r.member,
		ContentHash:    r.content,
		Version:        big.NewInt(r.version),
		State:          big.NewInt(r.state),
		AbsentBranch:   big.NewInt(branch),
		NfPathIndex:    big.NewInt(0),
		StatePathIndex: big.NewInt(0),
	}
	for i := range entry.NfPathElements {
		entry.NfPathElements[i] = big.NewInt(0)
	}
	for i := range entry.StatePathElements {
		entry.StatePathElements[i] = big.NewInt(0)
	}

	witness := s.nonInclusion[index]
	entry.Low = witness.LowValue
	entry.Next = witness.NextValue
	entry.NfPathIndex = new(big.Int).SetUint64(witness.LowIndex)
	for i, element := range witness.PathElements {
		entry.NfPathElements[i] = element
	}

	if r.state == 0 {
		return entry
	}
	proof, ok := s.stateProofs[s.stateLeaf[index]]
	if !ok {
		t.Fatalf("missing state proof for entry %d", index)
	}
	entry.StatePathIndex = new(big.Int).SetUint64(proof.PathIndex)
	for i, element := range proof.PathElements {
		entry.StatePathElements[i] = element
	}
	return entry
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
func hostPolicyHash(t *testing.T, rules []rule, inlineAssets []*big.Int, sources [NSources]source) *big.Int {
	t.Helper()
	elements := []*big.Int{policyTableDomain, big.NewInt(PolicyVersion)}
	for _, slot := range sources {
		elements = append(elements, big.NewInt(slot.listId), slot.owner)
	}
	elements = append(elements, big.NewInt(int64(len(rules))))
	for _, r := range rules {
		elements = append(elements, r.packed())
	}
	return spptest.MustHashChain(t, append(elements, inlineAssets...))
}

func hostUtxoHash(t *testing.T, w OpeningWires) *big.Int {
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
func dummyOpening(t *testing.T, blinding int64) OpeningWires {
	t.Helper()
	opening := zeroOpening()
	opening.Domain = big.NewInt(protocol.DummyDomain)
	opening.Blinding = big.NewInt(blinding)
	return opening
}

func zeroOpening() OpeningWires {
	return OpeningWires{
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

func zeroPoolEntry() RuleAnswerWires {
	entry := RuleAnswerWires{
		Enabled:        big.NewInt(0),
		Mode:           big.NewInt(0),
		ListId:         big.NewInt(0),
		Member:         big.NewInt(0),
		ContentHash:    big.NewInt(0),
		Version:        big.NewInt(0),
		State:          big.NewInt(0),
		AbsentBranch:   big.NewInt(0),
		Low:            big.NewInt(0),
		Next:           big.NewInt(0),
		NfPathIndex:    big.NewInt(0),
		StatePathIndex: big.NewInt(0),
	}
	for i := range entry.NfPathElements {
		entry.NfPathElements[i] = big.NewInt(0)
	}
	for i := range entry.StatePathElements {
		entry.StatePathElements[i] = big.NewInt(0)
	}
	return entry
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
