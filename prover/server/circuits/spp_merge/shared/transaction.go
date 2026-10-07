package shared

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction/shared"
)

const (
	InputTrees  = transaction.InputTrees
	UtxoDomain  = transaction.UtxoDomain
	DummyDomain = transaction.DummyDomain
)

// SupportedInputCounts are the merge input counts the circuits are compiled and
// keyed for, smallest first. A spender pads up to the next supported count with
// dummy slots, so the set does not need an entry per real input count.
//
// Merge instruction data carries no circuit selector: both the prover and the
// program derive the shape from the declared nullifier count, so every side
// must agree on which counts exist.
var SupportedInputCounts = []int{8, 24, 54}

func IsSupportedInputCount(n int) bool {
	for _, supported := range SupportedInputCounts {
		if supported == n {
			return true
		}
	}
	return false
}

type Input struct {
	Domain       frontend.Variable
	Amount       frontend.Variable
	Blinding     frontend.Variable
	RingDataHash frontend.Variable

	StatePathElements []frontend.Variable
	StatePathIndex    frontend.Variable
	TreeSlot          frontend.Variable

	NullifierLowValue        frontend.Variable
	NullifierNextValue       frontend.Variable
	NullifierLowPathElements []frontend.Variable
	NullifierLowPathIndex    frontend.Variable
}

type Output struct {
	RingDataHash frontend.Variable
}

type CommonPublicInputs struct {
	Nullifiers []frontend.Variable
	OutputHash frontend.Variable

	PrivateTxHash    frontend.Variable
	ExternalDataHash frontend.Variable
	AllowDummyInputs frontend.Variable

	TreeSlots    []transaction.TreeSlot
	OutputTreeID frontend.Variable
}

type Transaction struct {
	Inputs []Input
	Output Output

	MintChunks [MintChunkCount]frontend.Variable

	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable

	Public        CommonPublicInputs
	RingProgramID frontend.Variable

	OutputBlinding func(amount frontend.Variable) frontend.Variable
}

func NewInputs(n int) []Input {
	inputs := make([]Input, n)
	for i := range inputs {
		inputs[i].StatePathElements = make([]frontend.Variable, transaction.StateTreeHeight)
		inputs[i].NullifierLowPathElements = make([]frontend.Variable, transaction.NullifierTreeHeight)
	}
	return inputs
}

func NewCommonPublicInputs(n int) CommonPublicInputs {
	return CommonPublicInputs{
		Nullifiers: make([]frontend.Variable, n),
		TreeSlots:  transaction.NewTreeSlots(),
	}
}

func (p CommonPublicInputs) Prefix(api frontend.API) []frontend.Variable {
	return []frontend.Variable{
		gadget.RightHashChain4(api, p.Nullifiers),
		p.OutputHash,
		transaction.TreeSlotsHashChain(api, p.TreeSlots),
		p.OutputTreeID,
		p.PrivateTxHash,
		p.ExternalDataHash,
		p.AllowDummyInputs,
	}
}

func (t Transaction) ValidateLayout(numInputs int) error {
	if !IsSupportedInputCount(numInputs) {
		return fmt.Errorf("merge: unsupported input count %d, want one of %v", numInputs, SupportedInputCounts)
	}
	if got := len(t.Inputs); got != numInputs {
		return fmt.Errorf("merge: input count mismatch: got %d want %d", got, numInputs)
	}
	checks := []struct {
		name string
		got  int
		want int
	}{
		{"nullifier", len(t.Public.Nullifiers), numInputs},
		{"tree slot", len(t.Public.TreeSlots), transaction.InputTrees},
	}
	for _, check := range checks {
		if check.got != check.want {
			return fmt.Errorf(
				"merge: %s count mismatch: got %d want %d",
				check.name,
				check.got,
				check.want,
			)
		}
	}
	for i := range t.Inputs {
		if got := len(t.Inputs[i].StatePathElements); got != transaction.StateTreeHeight {
			return fmt.Errorf(
				"merge: input %d state path height: got %d want %d",
				i,
				got,
				transaction.StateTreeHeight,
			)
		}
		if got := len(t.Inputs[i].NullifierLowPathElements); got != transaction.NullifierTreeHeight {
			return fmt.Errorf(
				"merge: input %d nullifier path height: got %d want %d",
				i,
				got,
				transaction.NullifierTreeHeight,
			)
		}
	}
	return nil
}

func (t Transaction) Constrain(api frontend.API) {
	asset := gadget.HashChain(api, t.MintChunks[:])
	userOwnerHash := gadget.PoseidonHash(
		api,
		[]frontend.Variable{t.OwnerPkHash, t.UserNullifierPk},
	)

	nullifierPk := gadget.PoseidonHash(api, []frontend.Variable{t.UserNullifierSecret})
	api.AssertIsEqual(t.UserNullifierPk, nullifierPk)
	api.AssertIsBoolean(t.Public.AllowDummyInputs)
	isCompact := transaction.CompactSlots(api, t.Public.Nullifiers)
	for i := range t.Inputs {
		isDummy := api.IsZero(api.Sub(t.Inputs[i].Domain, DummyDomain))
		api.AssertIsEqual(
			api.Mul(api.Sub(1, t.Public.AllowDummyInputs), api.Sub(isDummy, isCompact[i])),
			0,
		)
	}

	api.AssertIsEqual(t.Inputs[0].Domain, UtxoDomain)

	inputHashes := make([]frontend.Variable, len(t.Inputs))
	nullifiers := make([]frontend.Variable, len(t.Inputs))
	ctx := mergeInputContext{
		OwnerHash:       userOwnerHash,
		NullifierSecret: t.UserNullifierSecret,
		Asset:           asset,
		RingProgramID:   t.RingProgramID,
		FirstNullifier:  frontend.Variable(0),
	}
	for i := range t.Inputs {
		tree := transaction.SelectTreeSlot(api, t.Inputs[i].TreeSlot, t.Public.TreeSlots, false)
		api.AssertIsDifferent(tree.UtxoRoot, 0)
		inputHashes[i], nullifiers[i] = constrainInput(api, t.Inputs[i], ctx, tree, i, isCompact[i])
		ctx.FirstNullifier = nullifiers[0]
	}
	transaction.AssertDistinctNullifiers(api, nullifiers, isCompact)

	sumInputs := frontend.Variable(0)
	for i := range t.Inputs {
		sumInputs = api.Add(sumInputs, t.Inputs[i].Amount)
	}

	var outputBlinding frontend.Variable
	if t.OutputBlinding != nil {
		outputBlinding = t.OutputBlinding(sumInputs)
	} else {
		outputBlinding = MergeOutputBlinding(api, t.UserNullifierSecret, nullifiers[0])
	}
	outputHash := constrainOutput(
		api,
		t.Output,
		t.Public.OutputHash,
		outputBlinding,
		userOwnerHash,
		asset,
		sumInputs,
		t.RingProgramID,
		t.Public.OutputTreeID,
	)

	addressNullifiers := make([]frontend.Variable, len(inputHashes))
	for i := range addressNullifiers {
		addressNullifiers[i] = frontend.Variable(0)
	}
	privateTxHash := transaction.PrivateTxHashCircuit(
		api,
		inputHashes,
		[]frontend.Variable{outputHash},
		addressNullifiers,
		transaction.DerivePrivateTxBlinding(api, nullifiers[0], t.UserNullifierSecret),
	)
	api.AssertIsEqual(privateTxHash, t.Public.PrivateTxHash)

	for i := range nullifiers {
		api.AssertIsEqual(t.Public.Nullifiers[i], nullifiers[i])
	}
}
