package ringrecords

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/helius-labs/zolana/prover/server/circuits/records"
)

// Vector is test-vectors/ring-records.json, written by custom-rings/member-registry/tests/ring_records_vector.rs.
type Vector struct {
	EmptyRoot    Hex           `json:"empty_root"`
	Applications []Application `json:"applications"`
	Openings     []struct {
		Member  Hex          `json:"member"`
		Root    Hex          `json:"root"`
		Present bool         `json:"present"`
		Record  VectorRecord `json:"record"`
		Path    VectorPath   `json:"path"`
	} `json:"openings"`
}

// Application is one queue segment the apply circuit proves, its pending writes before the authority's.
type Application struct {
	Name            string         `json:"name"`
	Pending         []QueuedWrite  `json:"pending"`
	AuthorityWrites []QueuedWrite  `json:"authority_writes"`
	OldRoot         Hex            `json:"old_root"`
	NewRoot         Hex            `json:"new_root"`
	OldNextIndex    uint64         `json:"old_next_index"`
	NewNextIndex    uint64         `json:"new_next_index"`
	ChainStart      Hex            `json:"chain_start"`
	ChainEnd        Hex            `json:"chain_end"`
	Count           int            `json:"count"`
	StatementHash   Hex            `json:"statement_hash"`
	Writes          []AppliedWrite `json:"writes"`
}

type QueuedWrite struct {
	Member    Hex    `json:"member"`
	Mask      uint64 `json:"mask"`
	Value     uint64 `json:"value"`
	EscrowKey Hex    `json:"escrow_key"`
	EntryHash Hex    `json:"entry_hash"`
	Chain     Hex    `json:"chain"`
}

type AppliedWrite struct {
	Member    Hex          `json:"member"`
	Mask      uint64       `json:"mask"`
	Value     uint64       `json:"value"`
	EscrowKey Hex          `json:"escrow_key"`
	Exists    bool         `json:"exists"`
	OldNext   Hex          `json:"old_next"`
	OldLists  uint64       `json:"old_lists"`
	OldEscrow Hex          `json:"old_escrow"`
	Slot      VectorPath   `json:"slot"`
	Low       VectorRecord `json:"low"`
	LowPath   VectorPath   `json:"low_path"`
}

type VectorRecord struct {
	Member    Hex    `json:"member"`
	Next      Hex    `json:"next"`
	Lists     uint64 `json:"lists"`
	EscrowKey Hex    `json:"escrow_key"`
}

type VectorPath struct {
	Index    uint64  `json:"index"`
	Siblings [][]Hex `json:"siblings"`
}

// Hex is a field element written as 64 big-endian hex digits.
type Hex struct{ *big.Int }

func (h *Hex) UnmarshalJSON(data []byte) error {
	var digits string
	if err := json.Unmarshal(data, &digits); err != nil {
		return err
	}
	value, ok := new(big.Int).SetString(digits, 16)
	if !ok || len(digits) != 64 {
		return fmt.Errorf("ring records vector: %q is not 32 hex bytes", digits)
	}
	h.Int = value
	return nil
}

func ReadVector(t testing.TB) Vector {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../test-vectors/ring-records.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v Vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func (w QueuedWrite) Entry() Entry {
	return Entry{Member: w.Member.Int, Mask: new(big.Int).SetUint64(w.Mask), Value: new(big.Int).SetUint64(w.Value), EscrowKey: w.EscrowKey.Int}
}

// Write is w as Apply returns it.
func (w AppliedWrite) Write(t testing.TB) Write {
	t.Helper()
	return Write{
		Entry:     Entry{Member: w.Member.Int, Mask: new(big.Int).SetUint64(w.Mask), Value: new(big.Int).SetUint64(w.Value), EscrowKey: w.EscrowKey.Int},
		Exists:    w.Exists,
		OldNext:   w.OldNext.Int,
		OldLists:  new(big.Int).SetUint64(w.OldLists),
		OldEscrow: w.OldEscrow.Int,
		Slot:      w.Slot.Path(t),
		Low:       w.Low.Record(),
		LowPath:   w.LowPath.Path(t),
	}
}

func (r VectorRecord) Record() Record {
	return Record{Member: r.Member.Int, Next: r.Next.Int, Lists: new(big.Int).SetUint64(r.Lists), EscrowKey: r.EscrowKey.Int}
}

func (p VectorPath) Path(t testing.TB) Path {
	t.Helper()
	path := Path{Index: p.Index}
	if len(p.Siblings) != records.Height {
		t.Fatalf("ring records vector: %d path levels", len(p.Siblings))
	}
	for level, row := range p.Siblings {
		if len(row) != records.Arity-1 {
			t.Fatalf("ring records vector: %d siblings at level %d", len(row), level)
		}
		for k, sibling := range row {
			path.Siblings[level][k] = sibling.Int
		}
	}
	return path
}
