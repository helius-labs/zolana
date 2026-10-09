package aes

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// SubstitutionLookup, SpreadByteLookup and ChunkParityLookup stand for the
// logderivlookup tables of spread_bytes.go during Lean extraction. Each lookup
// is an opaque predicate relating Index to one table entry; the table contents
// reach Lean separately and lookup soundness is an explicit assumption.
type SubstitutionLookup struct {
	Index frontend.Variable
}

func (SubstitutionLookup) DefineGadget(frontend.API) interface{} { panic("extraction-only") }

func (SubstitutionLookup) OpaqueOutputs() int { return 1 }

type SpreadByteLookup struct {
	Index frontend.Variable
}

func (SpreadByteLookup) DefineGadget(frontend.API) interface{} { panic("extraction-only") }

func (SpreadByteLookup) OpaqueOutputs() int { return 1 }

type ChunkParityLookup struct {
	Index frontend.Variable
}

func (ChunkParityLookup) DefineGadget(frontend.API) interface{} { panic("extraction-only") }

func (ChunkParityLookup) OpaqueOutputs() int { return 1 }

type opaqueTable struct {
	api    frontend.API
	gadget func(index frontend.Variable) abstractor.GadgetDefinition
}

var _ logderivlookup.Table = opaqueTable{}

func (opaqueTable) Insert(frontend.Variable) int { panic("extraction tables hold no entries") }

func (t opaqueTable) Lookup(indices ...frontend.Variable) []frontend.Variable {
	values := make([]frontend.Variable, len(indices))
	for i, index := range indices {
		values[i] = abstractor.Call(t.api, t.gadget(index))
	}
	return values
}

func newExtractionTables(t *spreadTables) *spreadTables {
	t.substitution = opaqueTable{t.api, func(index frontend.Variable) abstractor.GadgetDefinition {
		return SubstitutionLookup{Index: index}
	}}
	t.bytes = opaqueTable{t.api, func(index frontend.Variable) abstractor.GadgetDefinition {
		return SpreadByteLookup{Index: index}
	}}
	t.chunks = opaqueTable{t.api, func(index frontend.Variable) abstractor.GadgetDefinition {
		return ChunkParityLookup{Index: index}
	}}
	return t
}
