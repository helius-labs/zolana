package spptest

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	merkletree "github.com/helius-labs/zolana/prover/server/merkle-tree"
)

// MemberRecord mirrors the registry leaf, Poseidon(member, next, lists, escrowKey).
type MemberRecord struct {
	Member    *big.Int
	Next      *big.Int
	Lists     *big.Int
	EscrowKey *big.Int
}

func (r MemberRecord) Hash(t testing.TB) *big.Int {
	t.Helper()
	return MustPoseidon(t, 5, []*big.Int{r.Member, r.Next, r.Lists, r.EscrowKey})
}

// MemberRegistrySentinelNext is above every member.
func MemberRegistrySentinelNext() *big.Int {
	return new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
}

// MemberRegistry is the host twin of the ring's member registry, the sentinel
// occupies slot zero and inserts append.
type MemberRegistry struct {
	tree    merkletree.PoseidonTree
	records []MemberRecord
}

// MemberOpeningWitness proves a member present, or absent under its low record.
type MemberOpeningWitness struct {
	Present bool
	// Record is the member's record, or the low record when absent.
	Record MemberRecord
	Index  uint64
	Path   []big.Int
}

// MemberUpdateWitness is one update item with the paths its proof needs.
type MemberUpdateWitness struct {
	OldRoot   *big.Int
	NewRoot   *big.Int
	Member    *big.Int
	Exists    bool
	Next      *big.Int
	OldLists  *big.Int
	OldEscrow *big.Int
	Lists     *big.Int
	EscrowKey *big.Int
	Index     uint64
	// Path opens Index under the root the low record was relinked in.
	Path     []big.Int
	Low      MemberRecord
	LowIndex uint64
	LowPath  []big.Int
}

func NewMemberRegistry(t testing.TB, height int) *MemberRegistry {
	t.Helper()
	r := &MemberRegistry{tree: merkletree.NewTree(height)}
	r.set(t, 0, MemberRecord{Member: big.NewInt(0), Next: MemberRegistrySentinelNext(), Lists: big.NewInt(0), EscrowKey: big.NewInt(0)})
	return r
}

func (r *MemberRegistry) Root() *big.Int {
	root := r.tree.Root.Value()
	return &root
}

// NextIndex is the append slot.
func (r *MemberRegistry) NextIndex() uint64 {
	return uint64(len(r.records))
}

func (r *MemberRegistry) Path(index uint64) []big.Int {
	return r.tree.GetProofByIndex(int(index))
}

// Find returns the member's index, or the index of its low record.
func (r *MemberRegistry) Find(member *big.Int) (index int, present bool) {
	low := 0
	for i, record := range r.records {
		if record.Member.Cmp(member) == 0 {
			return i, true
		}
		if record.Member.Cmp(member) < 0 && record.Member.Cmp(r.records[low].Member) >= 0 {
			low = i
		}
	}
	return low, false
}

func (r *MemberRegistry) Opening(member *big.Int) MemberOpeningWitness {
	index, present := r.Find(member)
	return MemberOpeningWitness{Present: present, Record: r.records[index], Index: uint64(index), Path: r.Path(uint64(index))}
}

// Update writes lists and escrowKey for member, inserting it after its low record.
func (r *MemberRegistry) Update(t testing.TB, member, lists, escrowKey *big.Int) MemberUpdateWitness {
	t.Helper()
	index, present := r.Find(member)
	w := MemberUpdateWitness{OldRoot: r.Root(), Member: member, Exists: present, Lists: lists, EscrowKey: escrowKey,
		OldLists: big.NewInt(0), OldEscrow: big.NewInt(0)}
	if present {
		record := r.records[index]
		w.Next, w.OldLists, w.OldEscrow, w.Index = record.Next, record.Lists, record.EscrowKey, uint64(index)
		w.Path = r.Path(w.Index)
		r.set(t, index, MemberRecord{Member: member, Next: record.Next, Lists: lists, EscrowKey: escrowKey})
	} else {
		low := r.records[index]
		w.Low, w.LowIndex, w.LowPath = low, uint64(index), r.Path(uint64(index))
		w.Next, w.Index = low.Next, r.NextIndex()
		r.set(t, index, MemberRecord{Member: low.Member, Next: member, Lists: low.Lists, EscrowKey: low.EscrowKey})
		w.Path = r.Path(w.Index)
		r.set(t, int(w.Index), MemberRecord{Member: member, Next: low.Next, Lists: lists, EscrowKey: escrowKey})
	}
	w.NewRoot = r.Root()
	return w
}

// RegisterKey escrows Poseidon(nullifierPk, ctHash) for member and keeps its lists.
func (r *MemberRegistry) RegisterKey(t testing.TB, member, nullifierPk, ctHash *big.Int) MemberUpdateWitness {
	t.Helper()
	lists := big.NewInt(0)
	if index, present := r.Find(member); present {
		lists = r.records[index].Lists
	}
	return r.Update(t, member, lists, MustPoseidon(t, 3, []*big.Int{nullifierPk, ctHash}))
}

func (r *MemberRegistry) set(t testing.TB, index int, record MemberRecord) {
	t.Helper()
	r.tree.Update(index, *record.Hash(t))
	if index == len(r.records) {
		r.records = append(r.records, record)
		return
	}
	r.records[index] = record
}
