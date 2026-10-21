package registry_test

import (
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringrecords"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// The Rust registry and the host twin build the same witnesses, and the circuit accepts Rust's.
func TestApplyRecordsMatchesRustVectors(t *testing.T) {
	v := ringrecords.ReadVector(t)
	members := ringrecords.New(t)
	if members.Root().Cmp(v.EmptyRoot.Int) != 0 {
		t.Fatalf("empty root %x, Rust %x", members.Root(), v.EmptyRoot.Int)
	}
	for _, app := range v.Applications {
		t.Run(app.Name, func(t *testing.T) {
			queued := slices.Concat(app.Pending, app.AuthorityWrites)
			entries := make([]ringrecords.Entry, len(queued))
			chain := app.ChainStart.Int
			for i, q := range queued {
				entries[i] = q.Entry()
				hash := entryHash(t, entries[i])
				chain = spptest.MustPoseidon(t, 3, []*big.Int{chain, hash})
				if hash.Cmp(q.EntryHash.Int) != 0 || chain.Cmp(q.Chain.Int) != 0 {
					t.Fatalf("entry %d hash %x chain %x, Rust %x %x", i, hash, chain, q.EntryHash.Int, q.Chain.Int)
				}
			}
			n := registry.ApplyBatch
			if app.Count == 1 {
				n = 1
			}
			b := applyBatch(t, members, n, app.ChainStart.Int, entries...)
			c := b.circuit
			for name, pair := range map[string][2]*big.Int{
				"old root":       {spptest.AsBigInt(c.OldRoot), app.OldRoot.Int},
				"new root":       {spptest.AsBigInt(c.NewRoot), app.NewRoot.Int},
				"old next index": {spptest.AsBigInt(c.OldNextIndex), new(big.Int).SetUint64(app.OldNextIndex)},
				"new next index": {spptest.AsBigInt(c.NewNextIndex), new(big.Int).SetUint64(app.NewNextIndex)},
				"chain end":      {spptest.AsBigInt(c.ChainEnd), app.ChainEnd.Int},
				"statement":      {spptest.AsBigInt(c.PublicInputHash), app.StatementHash.Int},
			} {
				if pair[0].Cmp(pair[1]) != 0 {
					t.Fatalf("%s %x, Rust %x", name, pair[0], pair[1])
				}
			}
			for i, w := range app.Writes {
				rust := w.Write(t)
				if !sameWrite(b.writes[i], rust) {
					t.Fatalf("write %d differs from the Rust witness", i)
				}
				c.Writes[i] = writeWires(rust)
			}
			if err := solve(t, c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func sameWrite(a, b ringrecords.Write) bool {
	same := func(x, y []*big.Int) bool {
		return slices.EqualFunc(x, y, func(p, q *big.Int) bool { return p.Cmp(q) == 0 })
	}
	fields := func(w ringrecords.Write) []*big.Int {
		values := []*big.Int{w.Entry.Member, w.Entry.Mask, w.Entry.Value, w.Entry.EscrowKey, w.OldNext, w.OldLists, w.OldEscrow,
			w.Low.Member, w.Low.Next, w.Low.Lists, w.Low.EscrowKey, new(big.Int).SetUint64(w.Slot.Index), new(big.Int).SetUint64(w.LowPath.Index)}
		for _, path := range []ringrecords.Path{w.Slot, w.LowPath} {
			for _, row := range path.Siblings {
				values = append(values, row[:]...)
			}
		}
		return values
	}
	return a.Exists == b.Exists && same(fields(a), fields(b))
}
