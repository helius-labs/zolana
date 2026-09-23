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

	"zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/custom_rings/circuits/base/audittest"
	"zolana/prover/custom_rings/circuits/registry"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
)

// The host side of this test recomputes the whole statement outside the
// circuit, the audit block with crypto/ecdh and crypto/aes, the entry and
// policy hashing with the same iden3 Poseidon the Rust twins use, and the two
// SPP trees with the protocol helpers. Solving the compiled R1CS against that
// witness is the cross-check that the circuit computes what
// custom-rings/policy will recompute.

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
				c.TreeSlots[0].UtxoRoot = new(big.Int).Add(spptest.AsBigInt(c.TreeSlots[0].UtxoRoot), big.NewInt(1))
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
				c.Rules[0].ListMask, c.Rules[0].OppositeModeListMask = c.Rules[0].OppositeModeListMask, c.Rules[0].ListMask
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
	fmt.Printf("state_root           %s\n", hex32(s.trees[0].stateRoot))
	fmt.Printf("nullifier_root       %s\n", hex32(s.trees[0].nullifierRoot))
	fmt.Printf("private_tx_hash      %s\n", hex32(s.privateTxHash))
	fmt.Printf("public_input_hash    %s\n", hex32(s.publicInputHash))

	fmt.Printf("empty_policy_hash    %s\n", hex32(hostPolicy{sources: emptySources()}.hash(t)))
	oneMap := emptySources()
	oneMap[listAllow-1] = source{listId: listAllow, owner: s.ownOwnerHash}
	oneRule := []rule{{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listAllow)}}
	fmt.Printf("one_rule_policy_hash %s\n", hex32(hostPolicy{rules: oneRule, sources: oneMap}.hash(t)))
	twoMap := oneMap
	twoMap[listFrozen-1] = source{listId: listFrozen, owner: s.curatorOwnerHash}
	twoRules := append(oneRule, rule{subject: SubjectSender, mode: ModeAbsent, mask: listMask(listFrozen)})
	fmt.Printf("two_rule_policy_hash %s\n", hex32(hostPolicy{rules: twoRules, sources: twoMap}.hash(t)))
	mixedMap := emptySources()
	mixedMap[listBlock-1] = source{listId: listBlock, owner: s.ownOwnerHash}
	mixedMap[listApproval-1] = source{listId: listApproval, owner: s.ownOwnerHash}
	mixedRule := []rule{{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listApproval), altMask: listMask(listBlock)}}
	fmt.Printf("mixed_rule_policy_hash %s\n", hex32(hostPolicy{rules: mixedRule, sources: mixedMap}.hash(t)))
	perAssetRule := []rule{{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listAllow), guardTag: GuardAboveAmountByAsset}}
	fmt.Printf("per_asset_policy_hash %s\n", hex32(hostPolicy{
		rules:        perAssetRule,
		inlineAssets: []*big.Int{assetField(t, fill(0xd4))},
		inlineLimits: []uint64{123},
		sources:      oneMap,
	}.hash(t)))
	velocityRows := []velocityRow{{asset: assetField(t, fill(0xd4)), cap: 5000, cosign: 600}}
	fmt.Printf("velocity_policy_hash %s\n", hex32(hostPolicy{rules: oneRule, sources: oneMap, windowSlots: 216000, velocity: velocityRows}.hash(t)))

	f := defaultFixture()
	f.velocity = velocityFixtureDefault()
	f.velocity.spent = 700
	f.velocity.cosignAbove = 600
	f.velocity.approval = true
	v := newStatement(t, f)
	fmt.Printf("spend.address        %s\n", hex32(v.record.address))
	fmt.Printf("spend.commitment     %s\n", hex32(v.record.commitment))
	fmt.Printf("spend.data_hash      %s\n", hex32(v.record.dataHash))
	fmt.Printf("spend.utxo_hash      %s\n", hex32(hostUtxoHash(t, v.inputs[len(v.inputs)-1])))
	fmt.Printf("spend.next_commitment %s\n", hex32(v.record.nextCommitment))
	fmt.Printf("spend.next_data_hash %s\n", hex32(v.record.nextDataHash))
	fmt.Printf("spend.zero_commitment %s\n", hex32(hostCountersCommitment(t, big.NewInt(0), nil, nil)))
	fmt.Printf("velocity_public_input_hash %s\n", hex32(v.publicInputHash))

	capRows := []velocityRow{{asset: assetField(t, fill(0xd4)), cap: 5000, cosign: 600}}
	fmt.Printf("transfer_cap_policy_hash %s\n", hex32(hostPolicy{rules: oneRule, sources: oneMap, velocity: capRows}.hash(t)))
	cf := defaultFixture()
	cf.velocity = velocityFixtureDefault()
	cf.velocity.perTransfer = true
	cf.velocity.cosignAbove = 600
	cf.velocity.approval = true
	cv := newStatement(t, cf)
	fmt.Printf("transfer_cap_public_input_hash %s\n", hex32(cv.publicInputHash))
}

func TestNonzeroRevocationTailVector(t *testing.T) {
	baseHash, _ := new(big.Int).SetString("25266a07f9480618e9ab495065e3d2a4530ab8e2cefe44d6b5e7324466bb0093", 16)
	repeatedTarget, _ := new(big.Int).SetString("1111111111111111111111111111111111111111111111111111111111111111", 16)
	filled := func(value byte) *big.Int {
		data := make([]byte, 32)
		for i := range data {
			data[i] = value
		}
		return new(big.Int).SetBytes(data)
	}
	// Fact 1 reads slot 2, fact 0 slot 0.
	elements := []*big.Int{
		baseHash, filled(0x2a), filled(6), big.NewInt(9), filled(8), filled(10),
		big.NewInt(3), big.NewInt(1), big.NewInt(1), filled(0x0b), big.NewInt(2 << shared.TreeIndexBits),
		big.NewInt(0x42), repeatedTarget,
	}
	elements = append(elements, spptest.RepeatBigInt(big.NewInt(0), NListFacts-2)...)
	if got := hex32(spptest.MustHashChain(t, elements)); got != "0fea02bf7a8cfb1a2b99d9d69f90008e278e9d6fb56e94a253fafba9880fe31e" {
		t.Fatalf("nonzero revocation tail %s", got)
	}
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
	// nil keeps velocity off
	velocity *velocityFixture
}

func (f fixture) facts() []int {
	if f.rulesFree || (f.velocity != nil && f.velocity.rulesFree) {
		return nil
	}
	return f.listFacts
}

type velocityFixture struct {
	cap         uint64
	cosignAbove uint64
	// the record's counter for the transferred asset
	spent uint64
	// the record's window, windowIndex keeps the counter live
	recordWindow uint64
	// a same-owner output, inside the ring unless exit is set
	change uint64
	exit   bool
	// a third input of another owner
	secondSender bool
	approval     bool
	// extra rows beside the transferred asset
	rows []velocityRow
	// the record opened for another member
	recordOwner [32]byte
	// the successor keeps the spent version
	staleSuccessor bool
	// the record slot carries the Allow entry's data hash
	entryAsRecord bool
	// the counters are dropped from the witness
	forgetCounters bool
	// the sender's change satisfies no output owner rule, the change cases run rule free
	rulesFree bool
	// no window, the row caps one transfer with no record
	perTransfer bool
}

const (
	windowSlots = 100
	windowIndex = 3
	velocityCap = 5000
)

func velocityFixtureDefault() *velocityFixture {
	return &velocityFixture{cap: velocityCap, recordWindow: windowIndex}
}

type velocityRow struct {
	asset  *big.Int
	cap    uint64
	cosign uint64
}

type recordState struct {
	sender   *big.Int
	version  uint64
	window   uint64
	salt     *big.Int
	assets   []*big.Int
	spent    []uint64
	nextSalt *big.Int

	address        *big.Int
	commitment     *big.Int
	dataHash       *big.Int
	nextSpent      []uint64
	nextCommitment *big.Int
	nextDataHash   *big.Int
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
	// Index of the policy tree holding the entry, slot 0 is the address tree.
	slot     int
	listId   int64
	member   *big.Int
	state    int64
	version  int64
	content  *big.Int
	blinding int64
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
		Packed:               r.packed(),
		Subject:              big.NewInt(r.subject),
		Mode:                 big.NewInt(r.mode),
		ListMask:             big.NewInt(r.mask),
		OppositeModeListMask: big.NewInt(r.altMask),
		GuardTag:             big.NewInt(r.guardTag),
		Threshold:            new(big.Int).SetUint64(r.threshold),
	}
}

type statement struct {
	ownOwnerHash     *big.Int
	curatorOwnerHash *big.Int
	sources          [NSources]source
	rules            []rule
	inlineAssets     []*big.Int
	inlineLimits     []uint64
	windowSlots      uint64
	velocity         []velocityRow
	policyHash       *big.Int

	// The ring id every change output stays in.
	ringID      *big.Int
	windowIndex uint64
	approval    bool
	// nil without a velocity window
	record         *recordState
	forgetCounters bool

	entries []entry
	derived []derived
	// Spent nullifiers beside the entry addresses, tamper fixtures only.
	twinAddresses []*big.Int

	trees        []hostTree
	stateLeaf    map[int]uint64
	nonInclusion []protocol.NonInclusionWitness

	keyEscrow       bool
	keyRegistryRoot *big.Int
	// Aligned with outputs, nil opens nothing.
	outputKeys []*registry.KeyOpening

	inputs  []UtxoWires
	outputs []UtxoWires

	addressChain      *big.Int
	externalDataHash  *big.Int
	privateTxBlinding *big.Int
	privateTxHash     *big.Int
	publicInputHash   *big.Int

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
	if v := f.velocity; v != nil && v.rulesFree {
		f.rulesFree = true
	}

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
	asset := assetField(t, f.transferred)

	s.entries = []entry{
		allowedActive:      {listId: listAllow, member: allowed, state: EntryStateActive, version: 0, content: big.NewInt(0), blinding: 1},
		senderNotFrozen:    {listId: listFrozen, member: sender, state: 0, version: 0, content: big.NewInt(0), blinding: 2},
		blockedCleared:     {listId: listBlock, member: blocked, state: EntryStateCleared, version: 1, content: big.NewInt(0), blinding: 3},
		allowedNotBlocked:  {listId: listBlock, member: allowed, state: 0, version: 0, content: big.NewInt(0), blinding: 4},
		approvedActive:     {listId: listApproval, member: approved, state: EntryStateActive, version: 0, content: big.NewInt(0), blinding: 5},
		approvedBlocked:    {listId: listBlock, member: approved, state: EntryStateActive, version: 0, content: big.NewInt(0), blinding: 6},
		allowedNotApproved: {listId: listApproval, member: allowed, state: 0, version: 0, content: big.NewInt(0), blinding: 7},
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
		// The repointed slot derives the sender's Frozen address under the
		// own owner, an address the tree already holds.
		s.twinAddresses = []*big.Int{deriveRecord(t, s.ownOwnerHash, s.entries[senderNotFrozen]).address}
		s.sources[listFrozen-1].owner = s.ownOwnerHash
	}

	s.rules = []rule{
		{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listAllow)},
		{subject: SubjectSender, mode: ModeAbsent, mask: listMask(listFrozen)},
		{subject: SubjectAsset, mode: ModePresent, mask: listMask()},
		{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listApproval), guardTag: GuardAboveAmount, threshold: guardThreshold},
	}
	s.inlineAssets = []*big.Int{assetField(t, f.inlineAsset)}
	if f.secondInlineAsset != [32]byte{} {
		s.inlineAssets = append(s.inlineAssets, assetField(t, f.secondInlineAsset))
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
	s.ringID = big.NewInt(0x5a)
	if v := f.velocity; v != nil {
		if !v.perTransfer {
			s.windowSlots = windowSlots
			s.windowIndex = windowIndex
		}
		s.approval = v.approval
		s.forgetCounters = v.forgetCounters
		s.velocity = append([]velocityRow{{asset: asset, cap: v.cap, cosign: v.cosignAbove}}, v.rows...)
	}
	s.policyHash = s.policy().hash(t)

	s.keys = audittest.DefaultKeys(t)
	if f.keys != nil {
		s.keys = f.keys(s.keys)
	}
	s.buildTrees(t)
	secondAsset := asset
	if f.secondTransferred != [32]byte{} {
		secondAsset = assetField(t, f.secondTransferred)
	}
	s.buildTransaction(t, pkField(t, f.recipient), sender, asset, secondAsset, f.amount, f.secondAmount)
	if v := f.velocity; v != nil {
		if v.perTransfer {
			s.shapeTransferCap(t, v, sender)
		} else {
			s.addRecordSlots(t, v, sender, asset)
		}
	}
	return s
}

func (s *statement) addRecordSlots(t *testing.T, v *velocityFixture, sender, asset *big.Int) {
	t.Helper()
	recordMember := sender
	if v.recordOwner != [32]byte{} {
		recordMember = pkField(t, v.recordOwner)
	}
	assets := make([]*big.Int, len(s.velocity))
	for i, row := range s.velocity {
		assets[i] = row.asset
	}
	spent := make([]uint64, len(s.velocity))
	spent[0] = v.spent
	s.record = &recordState{
		sender:   recordMember,
		version:  4,
		window:   v.recordWindow,
		salt:     big.NewInt(0x5a17),
		assets:   assets,
		spent:    spent,
		nextSalt: big.NewInt(0x5a18),
	}

	s.shapeSpendInputs(t, v)
	senders := 1
	if v.secondSender {
		senders = 2
	}
	s.inputs = s.inputs[:senders]
	s.shapeSpendOutputs(v, sender)
	s.deriveRecord(t)
	if v.entryAsRecord {
		s.record.dataHash = s.derived[allowedActive].dataHash
	}
	if v.staleSuccessor {
		s.record.nextDataHash = hostRecordDataHash(t, s.record.address, s.record.sender, s.record.version, s.windowIndex, s.record.nextCommitment)
	}
	s.inputs = append(s.inputs, s.recordOpening(t, s.record.dataHash, 0x63))
	s.outputs = append(s.outputs, s.recordOpening(t, s.record.nextDataHash, 0x64))
	s.updateHashes(t)
}

func (s *statement) shapeSpendInputs(t *testing.T, v *velocityFixture) {
	t.Helper()
	s.inputs[0].Amount = new(big.Int).SetUint64(s.inputs[0].Amount.(*big.Int).Uint64() + v.change)
	if !v.secondSender {
		return
	}
	other := s.inputs[0]
	other.OwnerPkHash = pkField(t, fill(0xb4))
	other.Blinding = big.NewInt(0x61)
	s.inputs[1] = other
}

// Change inside the ring is excluded from the sender's outflow.
func (s *statement) shapeSpendOutputs(v *velocityFixture, sender *big.Int) {
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
}

// Limits without a window use money slots without a record pair.
func (s *statement) shapeTransferCap(t *testing.T, v *velocityFixture, sender *big.Int) {
	t.Helper()
	s.shapeSpendInputs(t, v)
	s.shapeSpendOutputs(v, sender)
	s.updateHashes(t)
}

func (s *statement) deriveRecord(t *testing.T) {
	t.Helper()
	r := s.record
	r.address = hostSpendAddress(t, s.ownOwnerHash, r.sender)
	r.commitment = hostCountersCommitment(t, r.salt, r.assets, r.spent)
	r.dataHash = hostRecordDataHash(t, r.address, r.sender, r.version, r.window, r.commitment)
	r.nextSpent = make([]uint64, len(s.velocity))
	for i, row := range s.velocity {
		previous := uint64(0)
		if r.window == s.windowIndex {
			previous = r.spent[i]
		}
		r.nextSpent[i] = previous + s.hostOutflow(row.asset)
	}
	r.nextCommitment = hostCountersCommitment(t, r.nextSalt, r.assets, r.nextSpent)
	r.nextDataHash = hostRecordDataHash(t, r.address, r.sender, r.version+1, s.windowIndex, r.nextCommitment)
}

func (s *statement) hostOutflow(asset *big.Int) uint64 {
	sender := s.inputs[0].OwnerPkHash.(*big.Int)
	inflow := uint64(0)
	for _, input := range s.inputs {
		if input.Domain.(*big.Int).Int64() == protocol.UtxoDomain && input.Asset.(*big.Int).Cmp(asset) == 0 {
			inflow += input.Amount.(*big.Int).Uint64()
		}
	}
	change := uint64(0)
	for _, output := range s.outputs {
		if output.Domain.(*big.Int).Int64() != protocol.UtxoDomain || output.Asset.(*big.Int).Cmp(asset) != 0 {
			continue
		}
		if output.OwnerPkHash.(*big.Int).Cmp(sender) == 0 && output.RingProgramID.(*big.Int).Cmp(s.ringID) == 0 {
			change += output.Amount.(*big.Int).Uint64()
		}
	}
	return inflow - change
}

// Spend records use the namespace owner with zero SOL in the address tree.
func (s *statement) recordOpening(t *testing.T, dataHash *big.Int, blinding int64) UtxoWires {
	t.Helper()
	return UtxoWires{
		Domain:        big.NewInt(protocol.UtxoDomain),
		TreeID:        big.NewInt(addressTreeID),
		OwnerPkHash:   pkField(t, fill(0x11)),
		NullifierPk:   spptest.MustNullifierPk(t, big.NewInt(0)),
		Asset:         solAssetField,
		Amount:        big.NewInt(0),
		Blinding:      big.NewInt(blinding),
		DataHash:      dataHash,
		RingDataHash:  big.NewInt(0),
		RingProgramID: big.NewInt(0),
	}
}

// hostTree is one policy tree, its id is addressTreeID plus its slot.
type hostTree struct {
	stateRoot     *big.Int
	nullifierRoot *big.Int
	stateProofs   map[uint64]protocol.StateTreeWitness
}

// buildTrees seeds the SPP roots the entry proofs open against, the created
// entries as leaves of their own tree and their addresses as spent nullifiers
// of the address tree.
func (s *statement) buildTrees(t *testing.T) {
	t.Helper()
	count := 1
	for _, r := range s.entries {
		count = max(count, r.slot+1)
	}
	leaves := make([]map[uint64]*big.Int, count)
	nullifiers := make([]*protocol.NullifierTree, count)
	for k := range leaves {
		leaves[k] = map[uint64]*big.Int{}
		nullifiers[k] = spptest.MustNewNullifierTree(t)
	}
	s.stateLeaf = map[int]uint64{}
	s.nonInclusion = nil
	for _, twin := range s.twinAddresses {
		if err := nullifiers[0].Insert(twin); err != nil {
			t.Fatalf("insert twin address: %v", err)
		}
	}
	for i, r := range s.entries {
		if r.state == 0 {
			continue
		}
		s.stateLeaf[i] = uint64(len(leaves[r.slot]))
		leaves[r.slot][s.stateLeaf[i]] = s.derived[i].utxoHash
		if err := nullifiers[0].Insert(s.derived[i].address); err != nil {
			t.Fatalf("insert entry address: %v", err)
		}
	}
	s.trees = make([]hostTree, count)
	for k := range s.trees {
		root, proofs := spptest.MustBuildSparseStateTree(t, leaves[k])
		s.trees[k] = hostTree{stateRoot: root, nullifierRoot: nullifiers[k].Root(), stateProofs: proofs}
	}
	// A created entry is unspent, a never created one has no address.
	for i, r := range s.entries {
		target := s.derived[i].nullifier
		if r.state == 0 {
			target = s.derived[i].address
		}
		s.nonInclusion = append(s.nonInclusion, spptest.MustNonInclusion(t, nullifiers[r.slot], target))
	}
}

func (s *statement) treeSlots(t *testing.T) []protocol.TreeSlot {
	t.Helper()
	populated := make([]protocol.TreeSlot, len(s.trees))
	for k, tree := range s.trees {
		populated[k] = protocol.TreeSlot{ID: big.NewInt(addressTreeID + int64(k)), UtxoRoot: tree.stateRoot, NullifierRoot: tree.nullifierRoot}
	}
	slots, err := protocol.PadTreeSlots(populated...)
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
			TreeID:        big.NewInt(0),
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

	s.addressChain = spptest.MustHashChain4(t, []*big.Int{big.NewInt(0), big.NewInt(0)})
	s.externalDataHash = big.NewInt(0x5eed)
	s.privateTxBlinding = big.NewInt(0x5b1d)
	s.updateHashes(t)
}

func buildAssignment(t *testing.T, f fixture) *CustomRingPolicyCircuit {
	t.Helper()
	return newStatement(t, f).assignment(t, f.facts())
}

func (s *statement) assignment(t *testing.T, listFacts []int) *CustomRingPolicyCircuit {
	t.Helper()
	s.updateHashes(t)
	wires := s.keys.AuditBlockWires(s.privateTxHash)
	c := &CustomRingPolicyCircuit{
		PublicInputHash:    s.publicInputHash,
		PrivateTxHash:      wires.PrivateTxHash,
		TxViewingSk:        wires.TxViewingSk,
		EphSk:              wires.EphSk,
		AuditorPk:          wires.AuditorPk,
		Salt:               wires.Salt,
		AddressChain:       s.addressChain,
		ExternalDataHash:   s.externalDataHash,
		PrivateTxBlinding:  s.privateTxBlinding,
		AddressTreeID:      big.NewInt(addressTreeID),
		RingID:             s.ringID,
		NamespaceOwnerHash: s.ownOwnerHash,
		WindowIndex:        new(big.Int).SetUint64(s.windowIndex),
		ApprovalRequired:   boolVar(s.approval),
		KeyEscrow:          boolVar(s.keyEscrow),
		KeyRegistryRoot:    s.registryRoot(),
		WindowSlots:        new(big.Int).SetUint64(s.windowSlots),
		Record:             s.recordWires(),
	}
	for i, slot := range s.sources {
		c.Sources[i] = SourceWires{ListId: big.NewInt(slot.listId), OwnerHash: slot.owner}
	}
	for i := range c.Velocity {
		c.Velocity[i] = VelocityRowWires{Asset: big.NewInt(0), Cap: big.NewInt(0), CosignAbove: big.NewInt(0)}
		c.VelocityCountSelected[i] = big.NewInt(0)
	}
	for i, row := range s.velocity {
		c.Velocity[i] = VelocityRowWires{
			Asset:       row.asset,
			Cap:         new(big.Int).SetUint64(row.cap),
			CosignAbove: new(big.Int).SetUint64(row.cosign),
		}
	}
	c.VelocityCountSelected[NVelocityAssets] = big.NewInt(0)
	c.VelocityCountSelected[len(s.velocity)] = big.NewInt(1)

	for i := range c.Inputs {
		c.Inputs[i] = zeroOpening()
		c.InputCountSelected[i] = big.NewInt(0)
	}
	for i, opening := range s.inputs {
		c.Inputs[i] = opening
	}
	c.InputCountSelected[len(s.inputs)-1] = big.NewInt(1)

	for k, slot := range s.treeSlots(t) {
		c.TreeSlots[k] = shared.TreeSlot{ID: slot.ID, UtxoRoot: slot.UtxoRoot, NullifierRoot: slot.NullifierRoot}
	}
	for i := range c.Outputs {
		c.Outputs[i] = zeroOpening()
		c.OutputCountSelected[i] = big.NewInt(0)
		c.OutputKeys[i] = zeroKeyOpening()
	}
	for i, opening := range s.outputs {
		c.Outputs[i] = opening
		if i < len(s.outputKeys) && s.outputKeys[i] != nil {
			c.OutputKeys[i] = *s.outputKeys[i]
		}
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
	s.publicInputHash = s.publicInputHashFor(t, listFacts)
	c.PublicInputHash = s.publicInputHash
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
		TreeSlot:              big.NewInt(int64(entry.slot)),
		Mode:                  big.NewInt(mode),
		ListId:                big.NewInt(entry.listId),
		Member:                entry.member,
		ContentHash:           entry.content,
		Version:               big.NewInt(entry.version),
		Blinding:              big.NewInt(entry.blinding),
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
	proof, ok := s.trees[entry.slot].stateProofs[s.stateLeaf[index]]
	if !ok {
		t.Fatalf("missing state proof for entry %d", index)
	}
	fact.StatePathIndex = new(big.Int).SetUint64(proof.PathIndex)
	for i, element := range proof.PathElements {
		fact.StatePathElements[i] = element
	}
	return fact
}

// Limits without a window do not consume the supplied counter openings.
func (s *statement) recordWires() RecordWires {
	wires := RecordWires{
		Version:    big.NewInt(0),
		Window:     big.NewInt(0),
		Commitment: big.NewInt(0),
		Salt:       big.NewInt(0),
		NextSalt:   big.NewInt(0),
	}
	for i := range wires.Assets {
		wires.Assets[i] = big.NewInt(0)
		wires.Spent[i] = big.NewInt(0)
	}
	r := s.record
	if r == nil {
		return wires
	}
	wires.Version = new(big.Int).SetUint64(r.version)
	wires.Window = new(big.Int).SetUint64(r.window)
	wires.Commitment = r.commitment
	wires.NextSalt = r.nextSalt
	if s.forgetCounters {
		return wires
	}
	wires.Salt = r.salt
	for i := range r.assets {
		wires.Assets[i] = r.assets[i]
		wires.Spent[i] = new(big.Int).SetUint64(r.spent[i])
	}
	return wires
}

func boolVar(value bool) *big.Int {
	if value {
		return big.NewInt(1)
	}
	return big.NewInt(0)
}

// addressTreeID is the raw id of the fixture's address tree, policy slot 0.
const addressTreeID = 7

// hostSpendAddress mirrors ring_policy::ListNamespace::spend_address.
func hostSpendAddress(t *testing.T, ownerHash, sender *big.Int) *big.Int {
	t.Helper()
	seed := spptest.MustPoseidon(t, 3, []*big.Int{SpendAddressDomain, sender})
	addressUtxoHash := spptest.MustPoseidon(t, 8, []*big.Int{
		big.NewInt(protocol.AddressDomain),
		big.NewInt(addressTreeID),
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		emptyRingHash,
		spptest.MustPoseidon(t, 3, []*big.Int{ownerHash, seed}),
	})
	return spptest.MustPoseidon(t, 4, []*big.Int{addressUtxoHash, seed, big.NewInt(0)})
}

// Counter commitments include canonical zero padding after active mints.
func hostCountersCommitment(t *testing.T, salt *big.Int, assets []*big.Int, spent []uint64) *big.Int {
	t.Helper()
	elements := []*big.Int{salt}
	for i := 0; i < NVelocityAssets; i++ {
		asset, counter := big.NewInt(0), big.NewInt(0)
		if i < len(assets) {
			asset = assets[i]
			counter = new(big.Int).SetUint64(spent[i])
		}
		elements = append(elements, asset, counter)
	}
	return spptest.MustHashChain(t, elements)
}

// hostRecordDataHash mirrors ring_policy::SpendRecord::data_hash.
func hostRecordDataHash(t *testing.T, address, sender *big.Int, version, window uint64, commitment *big.Int) *big.Int {
	t.Helper()
	return spptest.MustPoseidon(t, 7, []*big.Int{
		SpendRecordDomain,
		address,
		sender,
		new(big.Int).SetUint64(version),
		new(big.Int).SetUint64(window),
		commitment,
	})
}

// deriveRecord mirrors ring_policy::entry, the seed and address fixed by
// (listId, member) while the commitment moves with the state and version.
func deriveRecord(t *testing.T, ownerHash *big.Int, r entry) derived {
	t.Helper()
	seed := spptest.MustPoseidon(t, 4, []*big.Int{policyAddressDomain, big.NewInt(r.listId), r.member})
	addressUtxoHash := spptest.MustPoseidon(t, 8, []*big.Int{
		big.NewInt(protocol.AddressDomain),
		big.NewInt(addressTreeID),
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
	utxoHash := spptest.MustPoseidon(t, 8, []*big.Int{
		big.NewInt(protocol.UtxoDomain),
		big.NewInt(addressTreeID + int64(r.slot)),
		solAssetField,
		big.NewInt(0),
		dataHash,
		emptyRingHash,
		spptest.MustPoseidon(t, 3, []*big.Int{ownerHash, big.NewInt(r.blinding)}),
	})
	return derived{
		seed:      seed,
		address:   address,
		dataHash:  dataHash,
		utxoHash:  utxoHash,
		nullifier: spptest.MustPoseidon(t, 4, []*big.Int{utxoHash, big.NewInt(r.blinding), big.NewInt(0)}),
	}
}

type hostPolicy struct {
	rules        []rule
	inlineAssets []*big.Int
	inlineLimits []uint64
	sources      [NSources]source
	windowSlots  uint64
	velocity     []velocityRow
}

func (s *statement) policy() hostPolicy {
	return hostPolicy{
		rules:        s.rules,
		inlineAssets: s.inlineAssets,
		inlineLimits: s.inlineLimits,
		sources:      s.sources,
		windowSlots:  s.windowSlots,
		velocity:     s.velocity,
	}
}

// Mirrors ring_policy::RuleTable::hash.
func (p hostPolicy) hash(t *testing.T) *big.Int {
	t.Helper()
	elements := []*big.Int{policyTableDomain, big.NewInt(PolicyVersion)}
	for _, slot := range p.sources {
		elements = append(elements, big.NewInt(slot.listId), slot.owner)
	}
	elements = append(elements, big.NewInt(int64(len(p.rules))))
	elements = append(elements, big.NewInt(int64(len(p.inlineAssets))))
	elements = append(elements, big.NewInt(int64(len(p.velocity))))
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
	elements = append(elements, new(big.Int).SetUint64(p.windowSlots))
	for _, row := range p.velocity {
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

func disabledListFact() ListFactWires {
	fact := ListFactWires{
		Enabled:               big.NewInt(0),
		TreeSlot:              big.NewInt(0),
		Mode:                  big.NewInt(0),
		ListId:                big.NewInt(0),
		Member:                big.NewInt(0),
		ContentHash:           big.NewInt(0),
		Version:               big.NewInt(0),
		Blinding:              big.NewInt(0),
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

func zeroKeyOpening() registry.KeyOpening {
	opening := registry.KeyOpening{Next: 0, CtHash: 0, Index: 0}
	for i := range opening.Path {
		opening.Path[i] = 0
	}
	return opening
}

func (s *statement) registryRoot() *big.Int {
	if s.keyRegistryRoot == nil {
		return big.NewInt(0)
	}
	return s.keyRegistryRoot
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
