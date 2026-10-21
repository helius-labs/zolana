// Package ringpolicy builds honest witnesses of the policy keys from a World.
package ringpolicy

import (
	"math/big"
	"math/bits"
	"slices"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/policy"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringrecords"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

const (
	Sender = 1001
	Alice  = 1002
	Bob    = 1003
	Carol  = 1004
	Dave   = 1005
	Erin   = 1006
	Frank  = 1007
	Grace  = 1008
	AssetA = 2001
	AssetB = 2002
	AssetC = 2003
)

const (
	ringID            = 0x52494e47
	treeID            = 3
	inputChain        = 0x1c
	privateTxBlinding = 0x7b
)

var curatorRegistry = big.NewInt(0xc0ffee)

// World is one transfer with the registries and table it reads, Build derives every hash from it.
type World struct {
	// Outputs is the member key's capacity, zero selects the delegate key of Shape.
	Outputs                                int
	Shape                                  shared.Shape
	Anonymous, KeyEscrow, ApprovalRequired bool
	Sender                                 int64
	Table                                  Table
	Own, Curator                           map[int64]Record
	Slots, Inputs                          []Slot
	Public                                 []PublicSlot
}

// Table is a policy table of ringrecords list bits, a list reads the curator registry when Curator holds its bit.
type Table struct {
	Lists   []uint64
	Curator map[uint64]bool
	Rules   []Rule
	Inline  []InlineLimit
	Limits  []OutflowLimit
}

// Rule mirrors one Row of custom-rings/policy/src/rule_table.rs.
type Rule struct {
	Subject, Mode, Mask, Guard, Threshold, Alternative uint64
}

type InlineLimit struct {
	Asset int64
	Limit uint64
}

type OutflowLimit struct {
	Asset            int64
	Cap, CosignAbove uint64
}

// Record is one member's registry record, a registered member escrows Poseidon(nullifierPk, ctHash) of its outputs.
type Record struct {
	Lists      uint64
	Registered bool
}

// Slot is one output or input, a zero owner leaves it a dummy unless Unowned holds.
type Slot struct {
	Owner, Asset  int64
	Amount        uint64
	Exit, Unowned bool
}

type PublicSlot struct {
	Asset, Amount int64
}

// Rows are a table's used rows, Wires pads each list with zero rows to its capacity.
type Rows struct {
	Sources                           []policy.SourceWires
	Rules, InlineAssets, InlineLimits []frontend.Variable
	Limits                            []policy.OutflowLimitWires
}

type Witness struct {
	Member   *policy.MemberPolicyCircuit
	Delegate *policy.DelegatePolicyCircuit
}

func Confidential() World {
	return World{
		Outputs:   2,
		KeyEscrow: true,
		Sender:    Sender,
		Table: Table{
			Lists:  []uint64{ringrecords.AllowBit, ringrecords.BlockBit, ringrecords.FrozenBit},
			Rules:  []Rule{Require(policy.SubjectOutputOwner, ringrecords.AllowBit), Forbid(policy.SubjectSender, ringrecords.FrozenBit)},
			Limits: []OutflowLimit{{Asset: AssetA, Cap: 1000, CosignAbove: 500}},
		},
		Own:     map[int64]Record{Sender: Escrowed(ringrecords.AllowBit), Alice: Escrowed(ringrecords.AllowBit), Bob: Escrowed(ringrecords.AllowBit)},
		Curator: map[int64]Record{},
		Slots:   []Slot{{Owner: Alice, Asset: AssetA, Amount: 300}, {Owner: Sender, Asset: AssetA, Amount: 200}},
	}
}

func Anonymous() World {
	w := Confidential()
	w.Anonymous, w.KeyEscrow = true, false
	return w
}

func Four() World {
	w := Confidential()
	w.Outputs = 4
	w.Table.Rules = append(w.Table.Rules, Require(policy.SubjectAsset, ringrecords.AllowBit))
	w.Own[AssetA], w.Own[AssetB] = Record{Lists: ringrecords.AllowBit}, Record{Lists: ringrecords.AllowBit}
	w.Slots = []Slot{{Owner: Alice, Asset: AssetA, Amount: 100}, {Owner: Bob, Asset: AssetB, Amount: 1000}, {Owner: Sender, Asset: AssetA, Amount: 50}}
	return w
}

func Wide8() World {
	w := Four()
	w.Outputs = 8
	for _, m := range []int64{Carol, Dave, Erin, Frank, Grace} {
		w.Own[m] = Escrowed(ringrecords.AllowBit)
	}
	w.Own[AssetC] = Record{Lists: ringrecords.AllowBit}
	w.Slots = []Slot{
		{Owner: Alice, Asset: AssetA, Amount: 100}, {Owner: Bob, Asset: AssetA, Amount: 100},
		{Owner: Carol, Asset: AssetB, Amount: 100}, {Owner: Dave, Asset: AssetB, Amount: 100},
		{Owner: Erin, Asset: AssetC, Amount: 100}, {Owner: Sender, Asset: AssetA, Amount: 50},
		{Owner: Sender, Asset: AssetC, Amount: 50},
	}
	return w
}

func Wide16() World {
	w := Wide8()
	w.Outputs = 16
	w.Slots = append(w.Slots, Slot{Owner: Frank, Asset: AssetC, Amount: 100}, Slot{Owner: Grace, Asset: AssetB, Amount: 100}, Slot{Owner: Sender, Asset: AssetB, Amount: 50})
	return w
}

// MemberWorlds is the honest world of every member key capacity.
var MemberWorlds = map[int]func() World{2: Confidential, 4: Four, 8: Wide8, 16: Wide16}

func Delegate(shape shared.Shape) World {
	w := Four()
	w.Outputs, w.Shape = 0, shape
	w.Inputs = []Slot{{Owner: Sender, Asset: AssetA, Amount: 150}, {Owner: Sender, Asset: AssetB, Amount: 100}}[:min(2, shape.NInputs)]
	return w
}

func Escrowed(lists uint64) Record {
	return Record{Lists: lists, Registered: true}
}

// Require admits a subject on any of lists, as Rule::require_any does.
func Require(subject, lists uint64) Rule {
	return Rule{Subject: subject, Mode: policy.ModePresent, Mask: lists}
}

// Forbid refuses only a subject on every one of lists, as Rule::forbid_all does.
func Forbid(subject, lists uint64) Rule {
	return Rule{Subject: subject, Mode: policy.ModeAbsent, Mask: lists}
}

func (r Rule) Packed() *big.Int {
	packed := new(big.Int).Lsh(new(big.Int).SetUint64(r.Alternative), 96)
	packed.Or(packed, new(big.Int).Lsh(new(big.Int).SetUint64(r.Threshold), 32))
	return packed.Or(packed, new(big.Int).SetUint64(r.Subject|r.Mode<<8|r.Mask<<16|r.Guard<<24))
}

func (w World) Build(t testing.TB) Witness {
	t.Helper()
	return w.BuildRows(t, w.Table.rows())
}

// BuildRows builds the world under rows in place of Table's, the table a vector carries.
func (w World) BuildRows(t testing.TB, rows Rows) Witness {
	t.Helper()
	var b Witness
	if w.Outputs != 0 {
		c, err := policy.NewMemberPolicyCircuit(w.Outputs)
		if err != nil {
			t.Fatal(err)
		}
		b.Member = c
	} else {
		c, err := policy.NewDelegatePolicyCircuit(w.Shape)
		if err != nil {
			t.Fatal(err)
		}
		b.Delegate = c
	}
	p := b.Policy()
	own, curator := registry(t, w.Own), registry(t, w.Curator)
	entry := func(member int64) policy.Entry {
		return policy.Entry{Own: own.Opening(big.NewInt(member)).Wires(), Curator: curator.Opening(big.NewInt(member)).Wires()}
	}
	p.Table = rows.Wires()
	p.PolicyHash = TableHash(t, p.Table)
	p.RingID, p.OwnRoot, p.CuratorRoot = ringID, own.Root(), 0
	if slices.ContainsFunc(rows.Sources, func(s policy.SourceWires) bool { return spptest.AsBigInt(s.Registry).Sign() != 0 }) {
		p.CuratorRoot = curator.Root()
	}
	for k := range p.PublicAssets {
		p.PublicAssets[k], p.PublicAmounts[k] = 0, 0
		if k < len(w.Public) {
			p.PublicAssets[k], p.PublicAmounts[k] = w.Public[k].Asset, protocol.SignedToField(big.NewInt(w.Public[k].Amount))
		}
	}
	p.AddressChain, p.PrivateTxBlinding, p.SenderPkHash = 0, privateTxBlinding, w.Sender
	p.SenderEntry = entry(w.Sender)
	for o := range p.Outputs {
		s := pick(w.Slots, o)
		p.Outputs[o] = policy.OutputWires{UtxoWires: s.wires(0xb100 + int64(o)), CtHash: 0}
		if s.Owner != 0 {
			p.Outputs[o].CtHash = ctHash(s.Owner)
		}
		p.OwnerEntries[o], p.AssetEntries[o] = entry(s.Owner), entry(s.Asset)
	}
	if b.Delegate != nil {
		for i := range b.Delegate.Inputs {
			b.Delegate.Inputs[i] = pick(w.Inputs, i).wires(0xa100 + int64(i))
		}
	}
	if c := b.Member; c != nil {
		c.InputChain = inputChain
		c.Anonymous, c.KeyEscrow, c.ApprovalRequired = flag(w.Anonymous), flag(w.KeyEscrow), flag(w.ApprovalRequired)
		c.Sender = big.NewInt(w.Sender)
		if w.Anonymous {
			c.Sender = ringaudit.SenderCommitment(t, big.NewInt(w.Sender), big.NewInt(privateTxBlinding))
		}
	}
	b.Rehash(t)
	return b
}

func (b Witness) Policy() *policy.Policy {
	if b.Member != nil {
		return &b.Member.Policy
	}
	return &b.Delegate.Policy
}

func (b Witness) Assignment() frontend.Circuit {
	if b.Member != nil {
		return b.Member
	}
	return b.Delegate
}

// Rehash recomputes private_tx_hash from the slot wires after one changes, then the public input.
func (b Witness) Rehash(t testing.TB) {
	t.Helper()
	p := b.Policy()
	outputs := make([]*big.Int, len(p.Outputs))
	for o, w := range p.Outputs {
		outputs[o] = utxoHash(t, w.UtxoWires)
	}
	var chain *big.Int
	if b.Member != nil {
		chain = spptest.AsBigInt(b.Member.InputChain)
	} else {
		inputs := make([]*big.Int, len(b.Delegate.Inputs))
		for i, w := range b.Delegate.Inputs {
			inputs[i] = utxoHash(t, w)
		}
		chain = spptest.MustNonZeroHashChain(t, inputs)
	}
	p.PrivateTxHash = spptest.MustPoseidon(t, 5, []*big.Int{chain, spptest.MustNonZeroHashChain(t, outputs), spptest.AsBigInt(p.AddressChain), spptest.AsBigInt(p.PrivateTxBlinding)})
	b.Rebind(t)
}

// Rebind recomputes the public input after a statement value changes.
func (b Witness) Rebind(t testing.TB) {
	t.Helper()
	if c := b.Member; c != nil {
		c.PublicInputHash = spptest.MustHashChain4(t, spptest.ToBigInts(c.Statement()))
		return
	}
	b.Delegate.PublicInputHash = spptest.MustHashChain4(t, spptest.ToBigInts(b.Delegate.Statement()))
}

// TableHash mirrors EncodedRuleTable::hash, PolicyTableRate fields per call beside the accumulator.
func TableHash(t testing.TB, table policy.Table) *big.Int {
	t.Helper()
	fields := spptest.ToBigInts(table.Fields())
	accumulator := big.NewInt(0)
	for start := 0; start < len(fields); start += policy.PolicyTableRate {
		accumulator = spptest.MustPoseidon(t, policy.PolicyTableRate+2, append([]*big.Int{accumulator}, fields[start:start+policy.PolicyTableRate]...))
	}
	return accumulator
}

func (r Rows) Wires() policy.Table {
	var table policy.Table
	for i := range table.Sources {
		table.Sources[i] = pad(r.Sources, i, policy.SourceWires{ListID: 0, Registry: 0})
	}
	table.PolicyLen, table.InlineCount, table.LimitCount = len(r.Rules), len(r.InlineAssets), len(r.Limits)
	for i := range table.Rules {
		table.Rules[i] = pad(r.Rules, i, 0)
	}
	for i := range table.InlineAssets {
		table.InlineAssets[i], table.InlineLimits[i] = pad(r.InlineAssets, i, 0), pad(r.InlineLimits, i, 0)
	}
	for i := range table.Limits {
		table.Limits[i] = pad(r.Limits, i, policy.OutflowLimitWires{Asset: 0, Cap: 0, CosignAbove: 0})
	}
	return table
}

// rows serves the list of record bit i from source slot i, its list id i+1.
func (table Table) rows() Rows {
	sources := make([]policy.SourceWires, policy.NSources)
	for i := range sources {
		sources[i] = policy.SourceWires{ListID: 0, Registry: 0}
	}
	for _, list := range table.Lists {
		slot := bits.TrailingZeros64(list)
		registry := big.NewInt(0)
		if table.Curator[list] {
			registry = curatorRegistry
		}
		sources[slot] = policy.SourceWires{ListID: slot + 1, Registry: registry}
	}
	r := Rows{Sources: sources}
	for _, rule := range table.Rules {
		r.Rules = append(r.Rules, rule.Packed())
	}
	for _, inline := range table.Inline {
		r.InlineAssets, r.InlineLimits = append(r.InlineAssets, inline.Asset), append(r.InlineLimits, inline.Limit)
	}
	for _, limit := range table.Limits {
		r.Limits = append(r.Limits, policy.OutflowLimitWires{Asset: limit.Asset, Cap: limit.Cap, CosignAbove: limit.CosignAbove})
	}
	return r
}

// registry writes every member's record in ascending member order.
func registry(t testing.TB, records map[int64]Record) *ringrecords.Registry {
	t.Helper()
	r := ringrecords.New(t)
	ids := make([]int64, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		record := records[id]
		escrow := big.NewInt(0)
		if record.Registered {
			escrow = spptest.MustPoseidon(t, 3, []*big.Int{nullifierPk(id), ctHash(id)})
		}
		lists := new(big.Int).SetUint64(record.Lists)
		r.Apply(t, ringrecords.Entry{Member: big.NewInt(id), Mask: lists, Value: lists, EscrowKey: escrow})
	}
	return r
}

// wires opens the slot under treeID, a dummy keeps the asset and amount no sum counts.
func (s Slot) wires(blinding int64) base.UtxoWires {
	if s.Owner == 0 && !s.Unowned {
		return base.UtxoWires{
			Domain: shared.DummyDomain, TreeID: treeID, OwnerPkHash: 0, NullifierPk: 0, Asset: s.Asset, Amount: s.Amount,
			Blinding: blinding, DataHash: 0, RingDataHash: 0, RingProgramID: 0,
		}
	}
	ring := int64(ringID)
	if s.Exit {
		ring = 0
	}
	return base.UtxoWires{
		Domain: shared.UtxoDomain, TreeID: treeID, OwnerPkHash: s.Owner, NullifierPk: nullifierPk(s.Owner), Asset: s.Asset,
		Amount: s.Amount, Blinding: blinding, DataHash: 0, RingDataHash: 0, RingProgramID: ring,
	}
}

// utxoHash is the hash private_tx_hash chains for a slot, zero unless the slot is a UTXO.
func utxoHash(t testing.TB, w base.UtxoWires) *big.Int {
	t.Helper()
	if spptest.AsBigInt(w.Domain).Int64() != shared.UtxoDomain {
		return big.NewInt(0)
	}
	utxo := protocol.Utxo{
		Domain:        spptest.AsBigInt(w.Domain),
		Owner:         spptest.MustOwnerHash(t, spptest.AsBigInt(w.OwnerPkHash), spptest.AsBigInt(w.NullifierPk)),
		Asset:         spptest.AsBigInt(w.Asset),
		Amount:        spptest.AsBigInt(w.Amount),
		Blinding:      spptest.AsBigInt(w.Blinding),
		DataHash:      spptest.AsBigInt(w.DataHash),
		RingDataHash:  spptest.AsBigInt(w.RingDataHash),
		RingProgramID: spptest.AsBigInt(w.RingProgramID),
	}
	return spptest.MustUtxoHash(t, utxo, spptest.AsBigInt(w.TreeID))
}

func pick(slots []Slot, i int) Slot {
	return pad(slots, i, Slot{})
}

func pad[T any](rows []T, i int, zero T) T {
	if i < len(rows) {
		return rows[i]
	}
	return zero
}

func flag(set bool) int {
	if set {
		return 1
	}
	return 0
}

func nullifierPk(member int64) *big.Int { return big.NewInt(member + 500_000) }

func ctHash(member int64) *big.Int { return big.NewInt(member + 900_000) }
