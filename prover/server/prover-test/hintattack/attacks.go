package hintattack

import (
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
)

const CountHint = "/logderivarg.countHint"

func RequireConstraintRejection(t testing.TB, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("accepted")
	}
	var unsatisfied *cs_bn254.UnsatisfiedConstraintError
	if !errors.As(err, &unsatisfied) {
		t.Fatalf("stopped outside a constraint: %v", err)
	}
	if unsatisfied.Err == nil || !strings.Contains(unsatisfied.Err.Error(), " ⋅ ") || !strings.Contains(unsatisfied.Err.Error(), " != ") {
		t.Fatalf("stopped by the solver, not by a constraint equation: %v", err)
	}
	t.Logf("rejected: %v", err)
}

func SkipMissingLookupQueries(t testing.TB) solver.Option {
	t.Helper()
	honest, err := registeredHint(CountHint)
	if err != nil {
		t.Fatal(err)
	}
	if honest == nil {
		t.Fatalf("gnark no longer registers a hint ending in %s", CountHint)
	}
	return solver.OverrideHint(solver.GetHintID(honest), countQueriesInTable)
}

func countQueriesInTable(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) < 2 || !inputs[0].IsInt64() || !inputs[1].IsInt64() {
		return errors.New("lookup count: want the table length and the row length first")
	}
	nbTable, nbRow := int(inputs[0].Int64()), int(inputs[1].Int64())
	rows := inputs[2:]
	if nbRow < 1 || len(outputs) != nbTable || len(rows) < nbTable*nbRow || len(rows)%nbRow != 0 {
		return errors.New("lookup count: inputs do not match the table layout")
	}
	key := func(row []*big.Int) string {
		parts := make([]string, len(row))
		for i, v := range row {
			parts[i] = v.Text(16)
		}
		return strings.Join(parts, ",")
	}
	positions := make(map[string]int, nbTable)
	for i := range nbTable {
		positions[key(rows[i*nbRow:(i+1)*nbRow])] = i
	}
	counts := make([]int64, nbTable)
	for start := nbTable * nbRow; start < len(rows); start += nbRow {
		if i, ok := positions[key(rows[start:start+nbRow])]; ok {
			counts[i]++
		}
	}
	for i, out := range outputs {
		out.SetInt64(counts[i])
	}
	return nil
}

type substitutedLookup struct {
	*constraint.BlueprintLookupHint[constraint.U64]
	substitute  uint64
	substituted *atomic.Int64
}

func (b substitutedLookup) Solve(s constraint.Solver[constraint.U64], inst constraint.Instruction) error {
	nbEntries := uint64(inst.Calldata[1])
	indices, outside := readIndices(s, inst, nbEntries, b.substitute)
	if !outside {
		return b.BlueprintLookupHint.Solve(s, inst)
	}
	if b.substitute >= nbEntries {
		return fmt.Errorf("substitute index %d outside a table of %d entries", b.substitute, nbEntries)
	}
	entries := readEntries(s, b.EntriesCalldata, nbEntries)
	for i, index := range indices {
		s.SetValue(inst.WireOffset+uint32(i), entries[index])
	}
	b.substituted.Add(1)
	return nil
}

func readIndices(s constraint.Solver[constraint.U64], inst constraint.Instruction, nbEntries, fallback uint64) (indices []uint64, outside bool) {
	indices = make([]uint64, inst.Calldata[2])
	offset := 3
	for i := range indices {
		query, n := s.Read(inst.Calldata[offset:])
		offset += n
		index, ok := s.Uint64(query)
		if !ok || index >= nbEntries {
			index, outside = fallback, true
		}
		indices[i] = index
	}
	return indices, outside
}

func readEntries(s constraint.Solver[constraint.U64], calldata []uint32, nbEntries uint64) []constraint.U64 {
	entries := make([]constraint.U64, 0, nbEntries)
	for offset := 0; uint64(len(entries)) < nbEntries; {
		entry, n := s.Read(calldata[offset:])
		offset += n
		entries = append(entries, entry)
	}
	return entries
}

type forgedLookup struct {
	*constraint.BlueprintLookupHint[constraint.U64]
	target uint32
	forged *atomic.Int64
}

func (b forgedLookup) Solve(s constraint.Solver[constraint.U64], inst constraint.Instruction) error {
	if inst.WireOffset != b.target {
		return b.BlueprintLookupHint.Solve(s, inst)
	}
	nbEntries := uint64(inst.Calldata[1])
	indices, outside := readIndices(s, inst, nbEntries, 0)
	if outside {
		return fmt.Errorf("forged lookup: the targeted query is already outside the table")
	}
	entries := readEntries(s, b.EntriesCalldata, nbEntries)
	neighbour := indices[0] ^ 1
	if neighbour >= nbEntries {
		return fmt.Errorf("forged lookup: neighbour %d outside a table of %d entries", neighbour, nbEntries)
	}
	if entries[neighbour] == entries[indices[0]] {
		return fmt.Errorf("forged lookup: entries %d and %d are equal, the forgery would be a no-op", indices[0], neighbour)
	}
	s.SetValue(inst.WireOffset, entries[neighbour])
	for i, index := range indices[1:] {
		s.SetValue(inst.WireOffset+uint32(i+1), entries[index])
	}
	b.forged.Add(1)
	return nil
}

func ForgeLookupResult(t testing.TB, cs constraint.ConstraintSystem, nbEntries uint64) *atomic.Int64 {
	t.Helper()
	compiled, ok := cs.(*cs_bn254.R1CS)
	if !ok {
		t.Fatalf("compiled system is a %T", cs)
	}
	var target uint32
	found := false
	for _, packed := range compiled.Instructions {
		if _, ok := compiled.Blueprints[packed.BlueprintID].(*constraint.BlueprintLookupHint[constraint.U64]); !ok {
			continue
		}
		inst := packed.Unpack(&compiled.System)
		if uint64(inst.Calldata[1]) == nbEntries {
			target, found = inst.WireOffset, true
			break
		}
	}
	if !found {
		t.Fatalf("no lookup instruction queries a table of %d entries", nbEntries)
	}
	forged := new(atomic.Int64)
	original := slices.Clone(compiled.Blueprints)
	for i, blueprint := range compiled.Blueprints {
		if lookup, ok := blueprint.(*constraint.BlueprintLookupHint[constraint.U64]); ok {
			compiled.Blueprints[i] = forgedLookup{BlueprintLookupHint: lookup, target: target, forged: forged}
		}
	}
	t.Cleanup(func() { copy(compiled.Blueprints, original) })
	t.Logf("the first lookup on the table of %d entries answers query 0 with its neighbour's entry", nbEntries)
	return forged
}

func SubstituteOutOfRangeLookups(t testing.TB, cs constraint.ConstraintSystem, substitute uint64) *atomic.Int64 {
	t.Helper()
	compiled, ok := cs.(*cs_bn254.R1CS)
	if !ok {
		t.Fatalf("compiled system is a %T", cs)
	}
	substituted := new(atomic.Int64)
	original := slices.Clone(compiled.Blueprints)
	tables := 0
	for i, blueprint := range compiled.Blueprints {
		if lookup, ok := blueprint.(*constraint.BlueprintLookupHint[constraint.U64]); ok {
			compiled.Blueprints[i] = substitutedLookup{BlueprintLookupHint: lookup, substitute: substitute, substituted: substituted}
			tables++
		}
	}
	t.Cleanup(func() { copy(compiled.Blueprints, original) })
	t.Logf("%d lookup tables answer an out-of-range index with entry %d", tables, substitute)
	return substituted
}

// RegisteredHint is the one registered hint whose name ends in suffix.
func RegisteredHint(t testing.TB, suffix string) solver.Hint {
	t.Helper()
	hint, err := registeredHint(suffix)
	if err != nil || hint == nil {
		t.Fatalf("no single registered hint ends in %s: %v", suffix, err)
	}
	return hint
}

func registeredHint(suffix string) (solver.Hint, error) {
	var found []solver.Hint
	for _, h := range solver.GetRegisteredHints() {
		if strings.HasSuffix(solver.GetHintName(h), suffix) {
			found = append(found, h)
		}
	}
	switch len(found) {
	case 0:
		return nil, nil
	case 1:
		return found[0], nil
	default:
		names := make([]string, len(found))
		for i, h := range found {
			names[i] = solver.GetHintName(h)
		}
		return nil, fmt.Errorf("hint suffix %s is ambiguous: %v", suffix, names)
	}
}
