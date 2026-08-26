package transfer

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
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

	audit "zolana/prover/circuits/custom_ring"
	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
)

// The host side of this test recomputes the whole statement outside the
// circuit, the audit block with crypto/ecdh and crypto/aes, the record and
// policy hashing with the same iden3 Poseidon the Rust twins use, and the two
// SPP trees with the protocol helpers. Solving the compiled R1CS against that
// witness is the cross-check that the circuit computes what
// program-libs/ring-policy will recompute.

// auditEncInfo mirrors the unexported key-schedule info string of package
// audit.
const auditEncInfo = "CRING/adt1"

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
			name: "record mode swapped",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Pool[0].Mode = big.NewInt(ModeAbsent)
				return c
			},
		},
		{
			name: "record kind swapped",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Pool[0].Kind = big.NewInt(kindBlock)
				return c
			},
		},
		{
			name: "record proves a different member",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Pool[0].Member = new(big.Int).Add(spptest.AsBigInt(c.Pool[0].Member), big.NewInt(1))
				return c
			},
		},
		{
			name: "zero member",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Pool[0].Member = big.NewInt(0)
				return c
			},
		},
		{
			name: "present member claimed absent",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Pool[0].Mode = big.NewInt(ModeAbsent)
				c.Pool[0].AbsentBranch = big.NewInt(AbsentBranchNoAddress)
				return c
			},
		},
		{
			name: "cleared record claimed present",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Pool[2].Mode = big.NewInt(ModePresent)
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
			name: "record inclusion proof does not open the state root",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Pool[0].StatePathElements[0] = big.NewInt(1)
				return c
			},
		},
		{
			name: "record absence proof does not open the nullifier root",
			build: func(t *testing.T) *Circuit {
				c := validAssignment(t)
				c.Pool[1].NfPathElements[0] = big.NewInt(1)
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
			name: "live kind duplicated into a second slot in the witness",
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
	oneMap[kindAllow-1] = source{kind: kindAllow, owner: s.ownOwnerHash}
	oneRule := []rule{{subject: SubjectOutputOwner, mode: ModePresent, kind: kindAllow}}
	fmt.Printf("one_rule_policy_hash %s\n", hex32(hostPolicyHash(t, oneRule, nil, oneMap)))
	twoMap := oneMap
	twoMap[kindFrozen-1] = source{kind: kindFrozen, owner: s.curatorOwnerHash}
	twoRules := append(oneRule, rule{subject: SubjectSender, mode: ModeAbsent, kind: kindFrozen})
	fmt.Printf("two_rule_policy_hash %s\n", hex32(hostPolicyHash(t, twoRules, nil, twoMap)))
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
	amount          uint64
	transferred     [32]byte
	inlineAsset     [32]byte
	rulesFree       bool
	dropCuratorSlot bool
	curatorSlotOwn  bool
}

func defaultFixture() fixture {
	return fixture{amount: transferAmount, transferred: fill(0xd4), inlineAsset: fill(0xd4)}
}

// source is one host-side slot of the positional policy source map.
type source struct {
	kind  int64
	owner *big.Int
}

func emptySources() [NSources]source {
	var out [NSources]source
	for i := range out {
		out[i] = source{kind: 0, owner: big.NewInt(0)}
	}
	return out
}

// record is one host-side policy record, mirroring ring_policy::PolicyRecord.
type record struct {
	kind    int64
	member  *big.Int
	state   int64
	version int64
	payload *big.Int
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
	kind      int64
	guardTag  int64
	threshold uint64
}

func (r rule) packed() *big.Int {
	packed := new(big.Int).SetUint64(r.threshold)
	for _, part := range []int64{r.guardTag, r.kind, r.mode, r.subject} {
		packed.Or(packed.Lsh(packed, 8), big.NewInt(part))
	}
	return packed
}

func (r rule) wires() RuleWires {
	return RuleWires{
		Packed:    r.packed(),
		Subject:   big.NewInt(r.subject),
		Mode:      big.NewInt(r.mode),
		Kind:      big.NewInt(r.kind),
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

	records []record
	derived []derived

	stateRoot     *big.Int
	nullifierRoot *big.Int
	stateProofs   map[uint64]protocol.StateTreeWitness
	nonInclusion  []protocol.NonInclusionWitness

	inputs  []OpeningWires
	outputs []OpeningWires

	addressChain     *big.Int
	externalDataHash *big.Int
	privateTxHash    *big.Int
	publicInputHash  *big.Int

	txViewingSk [32]byte
	ephSk       [32]byte
	auditorPk   [65]byte
}

// newStatement builds a ring whose records allow the recipient, hold no Frozen
// record for the sender and carry a cleared Block record, a policy demanding
// all three plus a guarded Approval rule, and a two-in two-out transaction that
// satisfies them. The Frozen kind is sourced from a curator's records, every
// other kind from the ring's own.
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
	for _, kind := range []int64{kindAllow, kindBlock, kindApproval} {
		s.sources[kind-1] = source{kind: kind, owner: s.ownOwnerHash}
	}
	s.sources[kindFrozen-1] = source{kind: kindFrozen, owner: s.curatorOwnerHash}

	recipient := pkField(t, fill(0xa1))
	sender := pkField(t, fill(0xb2))
	blocked := pkField(t, fill(0xc3))
	asset := pkField(t, f.transferred)

	s.records = []record{
		{kind: kindAllow, member: recipient, state: RecordStateActive, version: 0, payload: big.NewInt(0)},
		{kind: kindFrozen, member: sender, state: 0, version: 0, payload: big.NewInt(0)},
		{kind: kindBlock, member: blocked, state: RecordStateCleared, version: 1, payload: big.NewInt(0)},
	}
	for _, r := range s.records {
		s.derived = append(s.derived, deriveRecord(t, s.sources[r.kind-1].owner, r))
	}
	// The knobs repoint the map after derivation, leaving the record fixtures
	// under the curator.
	if f.dropCuratorSlot {
		s.sources[kindFrozen-1] = source{kind: 0, owner: big.NewInt(0)}
	}
	if f.curatorSlotOwn {
		s.sources[kindFrozen-1].owner = s.ownOwnerHash
	}

	s.rules = []rule{
		{subject: SubjectOutputOwner, mode: ModePresent, kind: kindAllow},
		{subject: SubjectSender, mode: ModeAbsent, kind: kindFrozen},
		{subject: SubjectAsset, mode: ModePresent, kind: InlineKind},
		{subject: SubjectOutputOwner, mode: ModePresent, kind: kindApproval, guardTag: GuardAboveAmount, threshold: guardThreshold},
	}
	s.inlineAssets = []*big.Int{pkField(t, f.inlineAsset)}
	if f.rulesFree {
		s.rules = nil
		s.inlineAssets = nil
		s.sources = emptySources()
	}
	s.policyHash = hostPolicyHash(t, s.rules, s.inlineAssets, s.sources)

	s.buildTrees(t)
	s.buildTransaction(t, recipient, sender, asset, f.amount)
	return s
}

// buildTrees seeds the SPP roots the record proofs open against, the live
// records as state tree leaves and the addresses of the created records as
// spent nullifiers.
func (s *statement) buildTrees(t *testing.T) {
	t.Helper()
	root, proofs := spptest.MustBuildSparseStateTree(t, map[uint64]*big.Int{
		0: s.derived[0].utxoHash,
		1: s.derived[2].utxoHash,
	})
	s.stateRoot = root
	s.stateProofs = proofs

	tree := spptest.MustNewNullifierTree(t)
	for _, index := range []int{0, 2} {
		if err := tree.Insert(s.derived[index].address); err != nil {
			t.Fatalf("insert record address: %v", err)
		}
	}
	s.nullifierRoot = tree.Root()
	// The present and cleared records are unspent, the frozen record was never
	// created.
	s.nonInclusion = []protocol.NonInclusionWitness{
		spptest.MustNonInclusion(t, tree, s.derived[0].nullifier),
		spptest.MustNonInclusion(t, tree, s.derived[1].address),
		spptest.MustNonInclusion(t, tree, s.derived[2].nullifier),
	}
}

func (s *statement) buildTransaction(t *testing.T, recipient, sender, asset *big.Int, amount uint64) {
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
	s.outputs = []OpeningWires{created, dummyOpening(t, 0x54)}

	s.addressChain = spptest.MustHashChain(t, []*big.Int{big.NewInt(0), big.NewInt(0)})
	s.externalDataHash = big.NewInt(0x5eed)
	s.privateTxHash = spptest.MustPrivateTxHash(t,
		[]*big.Int{hostUtxoHash(t, s.inputs[0]), big.NewInt(0)},
		[]*big.Int{hostUtxoHash(t, s.outputs[0]), big.NewInt(0)},
		[]*big.Int{big.NewInt(0), big.NewInt(0)},
		s.externalDataHash,
	)

	s.txViewingSk = scalar(t, 0x11)
	s.ephSk = scalar(t, 0x22)
	auditorSk := scalar(t, 0x33)
	elements := hostAuditBlock(t, s.privateTxHash, s.txViewingSk, s.ephSk, auditorSk)
	s.auditorPk = auditorPublicKey(t, auditorSk)
	s.publicInputHash = spptest.MustHashChain(t, append(elements,
		s.policyHash, s.stateRoot, s.nullifierRoot))
}

func buildAssignment(t *testing.T, f fixture) *Circuit {
	t.Helper()
	s := newStatement(t, f)

	c := &Circuit{
		PublicInputHash:  s.publicInputHash,
		PrivateTxHash:    s.privateTxHash,
		AddressChain:     s.addressChain,
		ExternalDataHash: s.externalDataHash,
		StateRoot:        s.stateRoot,
		NullifierRoot:    s.nullifierRoot,
	}
	for i, slot := range s.sources {
		c.Sources[i] = SourceWires{Kind: big.NewInt(slot.kind), OwnerHash: slot.owner}
	}
	for i, b := range s.txViewingSk {
		c.TxViewingSk[i] = int(b)
	}
	for i, b := range s.ephSk {
		c.EphSk[i] = int(b)
	}
	for i, b := range s.auditorPk {
		c.AuditorPk[i] = int(b)
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
	disabled := rule{subject: SubjectOutputOwner, mode: ModePresent, kind: kindAllow}
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

	for e := range c.Pool {
		c.Pool[e] = zeroPoolEntry()
	}
	if f.rulesFree {
		return c
	}
	c.Pool[0] = s.poolEntry(t, 0, ModePresent, 0, 0)
	c.Pool[1] = s.poolEntry(t, 1, ModeAbsent, AbsentBranchNoAddress, 0)
	c.Pool[2] = s.poolEntry(t, 2, ModeAbsent, AbsentBranchCleared, 1)
	return c
}

func (s *statement) poolEntry(t *testing.T, index int, mode, branch int64, stateLeaf uint64) PoolEntryWires {
	t.Helper()
	r := s.records[index]
	entry := PoolEntryWires{
		Enabled:        big.NewInt(1),
		Mode:           big.NewInt(mode),
		Kind:           big.NewInt(r.kind),
		Member:         r.member,
		PayloadHash:    r.payload,
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

	if branch == AbsentBranchNoAddress {
		return entry
	}
	proof, ok := s.stateProofs[stateLeaf]
	if !ok {
		t.Fatalf("missing state proof for leaf %d", stateLeaf)
	}
	entry.StatePathIndex = new(big.Int).SetUint64(proof.PathIndex)
	for i, element := range proof.PathElements {
		entry.StatePathElements[i] = element
	}
	return entry
}

// deriveRecord mirrors ring_policy::record, the seed and address fixed by
// (kind, member) while the commitment moves with the state and version.
func deriveRecord(t *testing.T, ownerHash *big.Int, r record) derived {
	t.Helper()
	seed := spptest.MustPoseidon(t, 4, []*big.Int{policyAddressDomain, big.NewInt(r.kind), r.member})
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
		big.NewInt(r.kind),
		r.member,
		big.NewInt(r.state),
		big.NewInt(r.version),
		r.payload,
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

// hostPolicyHash mirrors ring_policy::Policy::hash.
func hostPolicyHash(t *testing.T, rules []rule, inlineAssets []*big.Int, sources [NSources]source) *big.Int {
	t.Helper()
	elements := []*big.Int{policyTableDomain, big.NewInt(PolicyVersion)}
	for _, slot := range sources {
		elements = append(elements, big.NewInt(slot.kind), slot.owner)
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

func zeroPoolEntry() PoolEntryWires {
	entry := PoolEntryWires{
		Enabled:        big.NewInt(0),
		Mode:           big.NewInt(0),
		Kind:           big.NewInt(0),
		Member:         big.NewInt(0),
		PayloadHash:    big.NewInt(0),
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

// hostAuditBlock recomputes chain elements 1 to 8 of package audit.
func hostAuditBlock(t *testing.T, privateTxHash *big.Int, txSk, ephSk, auditorSk [32]byte) []*big.Int {
	t.Helper()
	curve := ecdh.P256()
	txPriv, err := curve.NewPrivateKey(txSk[:])
	if err != nil {
		t.Fatalf("tx private key: %v", err)
	}
	ephPriv, err := curve.NewPrivateKey(ephSk[:])
	if err != nil {
		t.Fatalf("ephemeral private key: %v", err)
	}
	auditorPriv, err := curve.NewPrivateKey(auditorSk[:])
	if err != nil {
		t.Fatalf("auditor private key: %v", err)
	}

	txCompressed := compress(t, txPriv.PublicKey().Bytes())
	ephCompressed := compress(t, ephPriv.PublicKey().Bytes())
	auditorCompressed := compress(t, auditorPriv.PublicKey().Bytes())

	dh, err := ephPriv.ECDH(auditorPriv.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	dhLo, dhHi := hostPack32(t, dh)
	txLo, txHi := hostPack33(txCompressed)
	ephLo, ephHi := hostPack33(ephCompressed)
	auditorLo, auditorHi := hostPack33(auditorCompressed)

	sharedSecret := spptest.MustPoseidon(t, 8, []*big.Int{
		new(big.Int).SetUint64(uint64(audit.DomSepCRShared)),
		dhLo, dhHi,
		ephLo, ephHi,
		auditorLo, auditorHi,
	})
	key, nonce := hostKeySchedule(t, sharedSecret)
	ciphertext, err := protocol.HashBytes(hostCtrEncrypt(t, key, nonce, txSk[:]))
	ciphertextHash := spptest.MustHash(t, ciphertext, err)

	return []*big.Int{
		privateTxHash,
		txLo, txHi,
		auditorLo, auditorHi,
		ephLo, ephHi,
		ciphertextHash,
	}
}

func auditorPublicKey(t *testing.T, auditorSk [32]byte) [65]byte {
	t.Helper()
	priv, err := ecdh.P256().NewPrivateKey(auditorSk[:])
	if err != nil {
		t.Fatalf("auditor private key: %v", err)
	}
	return uncompressed(t, priv.PublicKey().Bytes())
}

// scalar builds a deterministic non-zero P-256 scalar below the group order.
func scalar(t *testing.T, seed byte) [32]byte {
	t.Helper()
	var out [32]byte
	for i := range out {
		out[i] = seed ^ byte(i)
	}
	out[0] = 0x01
	return out
}

func uncompressed(t *testing.T, publicKey []byte) [65]byte {
	t.Helper()
	if len(publicKey) != 65 {
		t.Fatalf("expected a 65-byte uncompressed key, got %d bytes", len(publicKey))
	}
	var out [65]byte
	copy(out[:], publicKey)
	return out
}

// compress mirrors p256.CompressPubkey host-side, (0x02 + parity(y)) || x.
func compress(t *testing.T, publicKey []byte) [33]byte {
	t.Helper()
	key := uncompressed(t, publicKey)
	var out [33]byte
	out[0] = 2 + (key[64] & 1)
	copy(out[1:], key[1:33])
	return out
}

// hostPack32 mirrors audit.Pack32To2FECircuit.
func hostPack32(t *testing.T, bytes []byte) (lo, hi *big.Int) {
	t.Helper()
	if len(bytes) != 32 {
		t.Fatalf("hostPack32: expected 32 bytes, got %d", len(bytes))
	}
	return new(big.Int).SetBytes(bytes[:31]), new(big.Int).SetUint64(uint64(bytes[31]))
}

// hostPack33 mirrors audit.Pack33To2FECircuit.
func hostPack33(key [33]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(key[:31]), new(big.Int).SetUint64(uint64(key[31])<<8 | uint64(key[32]))
}

// hostKeySchedule mirrors ve.KeySchedule with auditEncInfo as the info string.
func hostKeySchedule(t *testing.T, sharedSecret *big.Int) ([32]byte, [12]byte) {
	t.Helper()
	siloed := spptest.MustPoseidon(t, 4, []*big.Int{
		new(big.Int).SetUint64(uint64(ve.DomSepSilo)),
		sharedSecret,
		new(big.Int).SetBytes([]byte(auditEncInfo)),
	})
	keyLo := spptest.MustPoseidon(t, 3, []*big.Int{new(big.Int).SetUint64(uint64(ve.DomSepKey)), siloed})
	keyHi := spptest.MustPoseidon(t, 3, []*big.Int{new(big.Int).SetUint64(uint64(ve.DomSepKey + 1)), siloed})
	nonceRaw := spptest.MustPoseidon(t, 3, []*big.Int{new(big.Int).SetUint64(uint64(ve.DomSepNonce)), siloed})

	keyLoBytes := feBytes(keyLo)
	keyHiBytes := feBytes(keyHi)
	var key [32]byte
	copy(key[:16], keyHiBytes[16:])
	copy(key[16:], keyLoBytes[16:])

	var nonce [12]byte
	nonceBytes := feBytes(nonceRaw)
	copy(nonce[:], nonceBytes[20:])
	return key, nonce
}

func feBytes(value *big.Int) [32]byte {
	var out [32]byte
	value.FillBytes(out[:])
	return out
}

// hostCtrEncrypt mirrors aes.CTREncrypt, the counter block incremented once
// before the first block, leaving nonce || 2 for the first keystream block.
func hostCtrEncrypt(t *testing.T, key [32]byte, nonce [12]byte, plaintext []byte) []byte {
	t.Helper()
	block, err := stdaes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	var counter [16]byte
	copy(counter[:12], nonce[:])
	counter[15] = 2

	ciphertext := make([]byte, len(plaintext))
	cipher.NewCTR(block, counter[:]).XORKeyStream(ciphertext, plaintext)
	return ciphertext
}
