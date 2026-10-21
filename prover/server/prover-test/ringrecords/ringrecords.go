// Package ringrecords is the host twin of circuits/records for the Go tests.
package ringrecords

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana/prover/server/circuits/records"
	"github.com/helius-labs/zolana/prover/server/prover-test/poseidon"
)

// FieldMax is q-1, the sentinel's next, above every member.
var FieldMax = new(big.Int).Sub(poseidon.Modulus, big.NewInt(1))

// Record list bits mirror ListId::record_bit in custom-rings/policy/src/list.rs.
const (
	AllowBit  = 1 << 0
	BlockBit  = 1 << 1
	FrozenBit = 1 << 2
	EscrowBit = 1 << 7
)

// Record mirrors records.Record.
type Record struct {
	Member, Next, Lists, EscrowKey *big.Int
}

func (r Record) Hash(t testing.TB) *big.Int {
	t.Helper()
	return mustHash(t, r.Member, r.Next, r.Lists, r.EscrowKey)
}

// Path mirrors records.QuadPath.
type Path struct {
	Index    uint64
	Siblings [records.Height][records.Arity - 1]*big.Int
}

func (p Path) Wires() records.QuadPath {
	w := records.QuadPath{Index: p.Index}
	for level, siblings := range p.Siblings {
		for k, sibling := range siblings {
			w.Siblings[level][k] = new(big.Int).Set(sibling)
		}
	}
	return w
}

// Root mirrors records.QuadPath.Root.
func (p Path) Root(t testing.TB, leaf *big.Int) *big.Int {
	t.Helper()
	node := leaf
	for level, siblings := range p.Siblings {
		digit := int(p.Index>>(2*level)) & (records.Arity - 1)
		children := append(append(append([]*big.Int{}, siblings[:digit]...), node), siblings[digit:]...)
		node = mustHash(t, children...)
	}
	return node
}

// Opening opens Record, the member's own when Present, else the low record bracketing it.
type Opening struct {
	Present bool
	Record  Record
	Path    Path
}

// Wires zeroes the unused half.
func (o Opening) Wires() records.QuadOpening {
	w := records.QuadOpening{Present: 0, Next: 0, Lists: 0, EscrowKey: 0, LowMember: 0, LowNext: 0, LowLists: 0, LowEscrow: 0, Path: o.Path.Wires()}
	r := o.Record
	if o.Present {
		w.Present, w.Next, w.Lists, w.EscrowKey = 1, copied(r.Next), copied(r.Lists), copied(r.EscrowKey)
		return w
	}
	w.LowMember, w.LowNext, w.LowLists, w.LowEscrow = copied(r.Member), copied(r.Next), copied(r.Lists), copied(r.EscrowKey)
	return w
}

// RecordWires expects a present member.
func (o Opening) RecordWires() records.QuadRecordOpening {
	r := o.Record
	return records.QuadRecordOpening{Next: copied(r.Next), Lists: copied(r.Lists), EscrowKey: copied(r.EscrowKey), Path: o.Path.Wires()}
}

// UnreadRecordWires is the all-zero opening the prover assigns where a proof reads no record.
func UnreadRecordWires() records.QuadRecordOpening {
	zero := big.NewInt(0)
	return Opening{Record: Record{Next: zero, Lists: zero, EscrowKey: zero}, Path: zeroPath()}.RecordWires()
}

// Value lies inside Mask, as the program queues an entry.
type Entry struct {
	Member, Mask, Value, EscrowKey *big.Int
}

type Write struct {
	Entry                        Entry
	Exists                       bool
	OldNext, OldLists, OldEscrow *big.Int
	Slot                         Path // the member's leaf or the next empty leaf, after the relink for an insert
	Low                          Record
	LowPath                      Path
}

// Registry keeps the sentinel at index 0 and appends every insert.
type Registry struct {
	records []Record
	nodes   [records.Height + 1]map[uint64]*big.Int
	empty   [records.Height + 1]*big.Int
}

func New(t testing.TB) *Registry {
	t.Helper()
	r := &Registry{}
	r.empty[0] = big.NewInt(0)
	for level := 1; level <= records.Height; level++ {
		e := r.empty[level-1]
		r.empty[level] = mustHash(t, e, e, e, e)
	}
	for level := range r.nodes {
		r.nodes[level] = map[uint64]*big.Int{}
	}
	r.set(t, 0, Record{Member: big.NewInt(0), Next: FieldMax, Lists: big.NewInt(0), EscrowKey: big.NewInt(0)})
	return r
}

func (r *Registry) Root() *big.Int {
	return new(big.Int).Set(r.node(records.Height, 0))
}

func (r *Registry) NextIndex() uint64 {
	return uint64(len(r.records))
}

func (r *Registry) Opening(member *big.Int) Opening {
	index, present := r.find(member)
	return Opening{Present: present, Record: r.records[index], Path: r.Path(index)}
}

// Apply mirrors the apply circuit and returns the write's witness.
func (r *Registry) Apply(t testing.TB, e Entry) Write {
	t.Helper()
	// The program queues only members in [1, q-2] and values inside their mask.
	if e.Member.Sign() <= 0 || e.Member.Cmp(FieldMax) >= 0 || new(big.Int).AndNot(e.Value, e.Mask).Sign() != 0 {
		t.Fatalf("ring records: the program never queues %+v", e)
	}
	zero := big.NewInt(0)
	index, present := r.find(e.Member)
	if present {
		old := r.records[index]
		w := Write{Entry: e, Exists: true, OldNext: old.Next, OldLists: old.Lists, OldEscrow: old.EscrowKey,
			Slot: r.Path(index), Low: Record{zero, zero, zero, zero}, LowPath: zeroPath()}
		r.set(t, index, Record{Member: e.Member, Next: old.Next, Lists: masked(old.Lists, e), EscrowKey: fillOnce(old.EscrowKey, e.EscrowKey)})
		return w
	}
	low, next := r.records[index], r.NextIndex()
	w := Write{Entry: e, OldNext: low.Next, OldLists: zero, OldEscrow: zero, Slot: r.Path(next), Low: low, LowPath: r.Path(index)}
	if masked(zero, e).Sign() == 0 && e.EscrowKey.Sign() == 0 {
		return w
	}
	return r.Insert(t, e)
}

// Insert relinks and appends e's record even when empty, a forged insert Apply never makes.
func (r *Registry) Insert(t testing.TB, e Entry) Write {
	t.Helper()
	zero := big.NewInt(0)
	index, _ := r.find(e.Member)
	low, next := r.records[index], r.NextIndex()
	w := Write{Entry: e, OldNext: low.Next, OldLists: zero, OldEscrow: zero, Low: low, LowPath: r.Path(index)}
	r.set(t, index, Record{Member: low.Member, Next: e.Member, Lists: low.Lists, EscrowKey: low.EscrowKey})
	w.Slot = r.Path(next)
	r.set(t, next, Record{Member: e.Member, Next: low.Next, Lists: masked(zero, e), EscrowKey: e.EscrowKey})
	return w
}

// find returns member's index, or the index of the record with the largest member below it.
func (r *Registry) find(member *big.Int) (uint64, bool) {
	low := uint64(0)
	for i, record := range r.records {
		switch record.Member.Cmp(member) {
		case 0:
			return uint64(i), true
		case -1:
			if record.Member.Cmp(r.records[low].Member) > 0 {
				low = uint64(i)
			}
		}
	}
	return low, false
}

// Path opens the leaf at index, an empty leaf past the next index included.
func (r *Registry) Path(index uint64) Path {
	p := Path{Index: index}
	for level := range p.Siblings {
		node := index >> (2 * level)
		k := 0
		for child := node &^ (records.Arity - 1); k < records.Arity-1; child++ {
			if child != node {
				p.Siblings[level][k] = new(big.Int).Set(r.node(level, child))
				k++
			}
		}
	}
	return p
}

func zeroPath() Path {
	p := Path{}
	for level := range p.Siblings {
		for k := range p.Siblings[level] {
			p.Siblings[level][k] = big.NewInt(0)
		}
	}
	return p
}

func (r *Registry) node(level int, index uint64) *big.Int {
	if node, ok := r.nodes[level][index]; ok {
		return node
	}
	return r.empty[level]
}

func (r *Registry) set(t testing.TB, index uint64, record Record) {
	t.Helper()
	if index == uint64(len(r.records)) {
		r.records = append(r.records, record)
	} else {
		r.records[index] = record
	}
	r.nodes[0][index] = record.Hash(t)
	for level := 0; level < records.Height; level++ {
		parent := index >> (2 * (level + 1))
		first := parent * records.Arity
		r.nodes[level+1][parent] = mustHash(t, r.node(level, first), r.node(level, first+1), r.node(level, first+2), r.node(level, first+3))
	}
}

func masked(lists *big.Int, e Entry) *big.Int {
	return new(big.Int).Or(new(big.Int).AndNot(lists, e.Mask), e.Value)
}

func fillOnce(old, key *big.Int) *big.Int {
	if old.Sign() != 0 {
		return old
	}
	return key
}

func copied(v *big.Int) *big.Int {
	return new(big.Int).Set(v)
}

func mustHash(t testing.TB, inputs ...*big.Int) *big.Int {
	t.Helper()
	hash, err := poseidon.Hash(inputs)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
