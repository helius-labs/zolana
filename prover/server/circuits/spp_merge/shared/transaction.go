// Package shared holds the witness building blocks and constraints shared by
// the default and policy-ring SPP merge circuits.
package shared

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction/shared"
)

// MergeInputs is the fixed merge shape. Fewer real inputs use dummy slots.
const (
	MergeInputs = 8
	InputTrees  = transaction.InputTrees
	UtxoDomain  = transaction.UtxoDomain
	DummyDomain = transaction.DummyDomain
)

// Input contains the free per-slot merge witness. The circuit supplies the
// shared owner, asset, data hash, and ring program when reconstructing its UTXO.
type Input struct {
	Domain       frontend.Variable
	Amount       frontend.Variable
	Blinding     frontend.Variable
	RingDataHash frontend.Variable

	StatePathElements []frontend.Variable
	StatePathIndex    frontend.Variable
	// TreeSlot selects the public tree slot this input is spent from.
	TreeSlot frontend.Variable

	NullifierLowValue        frontend.Variable
	NullifierNextValue       frontend.Variable
	NullifierLowPathElements []frontend.Variable
	NullifierLowPathIndex    frontend.Variable
}

// Output contains the merged output's only free leaf field. The circuit
// derives its owner, asset, amount, domain, data hash, ring program, and
// blinding (see MergeOutputBlinding).
type Output struct {
	RingDataHash frontend.Variable
}

// CommonPublicInputs contains the prover-supplied public-input-hash components
// shared by both merge rails. Only the final PublicInputHash is gnark-public;
// Constrain binds every derived component below to its supplied signal.
type CommonPublicInputs struct {
	Nullifiers []frontend.Variable
	OutputHash frontend.Variable

	PrivateTxHash    frontend.Variable
	ExternalDataHash frontend.Variable
	AllowDummyInputs frontend.Variable

	// Input tree slots: raw u16 tree ids and utxo roots.
	TreeIDs       []frontend.Variable
	UtxoTreeRoots []frontend.Variable
	// One nullifier root for every input.
	NullifierTreeRoot frontend.Variable
	// Raw u16 id of the output tree.
	OutputTreeID frontend.Variable
}

// Transaction is the common merge statement over a wrapper-owned witness.
// RingProgramID is 0 on the default rail and the ring's public signal on the
// policy-ring rail.
type Transaction struct {
	Inputs []Input
	Output Output

	Asset frontend.Variable

	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable

	Public        CommonPublicInputs
	RingProgramID frontend.Variable
}

// Derived contains the owner identity a wrapper may publish in its
// public-input-hash preimage.
type Derived struct {
	OwnerPkHash frontend.Variable
}

// NewInputs allocates the fixed merge input slots and their Merkle paths.
func NewInputs() []Input {
	inputs := make([]Input, MergeInputs)
	for i := range inputs {
		inputs[i].StatePathElements = make([]frontend.Variable, transaction.StateTreeHeight)
		inputs[i].NullifierLowPathElements = make([]frontend.Variable, transaction.NullifierTreeHeight)
	}
	return inputs
}

// NewCommonPublicInputs allocates the per-input public signal slices.
func NewCommonPublicInputs() CommonPublicInputs {
	return CommonPublicInputs{
		Nullifiers:    make([]frontend.Variable, MergeInputs),
		TreeIDs:       make([]frontend.Variable, transaction.InputTrees),
		UtxoTreeRoots: make([]frontend.Variable, transaction.InputTrees),
	}
}

// Prefix returns the common public-input-hash preimage prefix.
func (p CommonPublicInputs) Prefix(api frontend.API) []frontend.Variable {
	return []frontend.Variable{
		gadget.HashChain(api, p.Nullifiers),
		p.OutputHash,
		gadget.HashChain(api, p.TreeIDs),
		gadget.HashChain(api, p.UtxoTreeRoots),
		p.NullifierTreeRoot,
		p.OutputTreeID,
		p.PrivateTxHash,
		p.ExternalDataHash,
		p.AllowDummyInputs,
	}
}

// ValidateLayout checks every slice indexed by the fixed merge skeleton before
// Constrain emits any constraints.
func (t Transaction) ValidateLayout(numInputs int) error {
	if numInputs != MergeInputs {
		return fmt.Errorf("merge: NumInputs must be %d, got %d", MergeInputs, numInputs)
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
		{"tree id", len(t.Public.TreeIDs), transaction.InputTrees},
		{"utxo tree root", len(t.Public.UtxoTreeRoots), transaction.InputTrees},
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

// Constrain proves the common merge statement and binds every supplied common
// public-input-hash component to its in-circuit derivation.
func (t Transaction) Constrain(api frontend.API) (Derived, error) {
	userOwnerHash := gadget.PoseidonHash(
		api,
		[]frontend.Variable{t.OwnerPkHash, t.UserNullifierPk},
	)

	nullifierPk := gadget.PoseidonHash(api, []frontend.Variable{t.UserNullifierSecret})
	api.AssertIsEqual(t.UserNullifierPk, nullifierPk)
	api.AssertIsBoolean(t.Public.AllowDummyInputs)
	for i := range t.Inputs {
		isDummy := api.IsZero(api.Sub(t.Inputs[i].Domain, DummyDomain))
		api.AssertIsEqual(
			api.Mul(api.Sub(1, t.Public.AllowDummyInputs), isDummy),
			0,
		)
	}

	// Slot zero must be a real input. Constrain it first so its genuine,
	// single-use nullifier can seed the output blinding and dummy nullifiers.
	api.AssertIsEqual(t.Inputs[0].Domain, UtxoDomain)

	inputHashes := make([]frontend.Variable, len(t.Inputs))
	nullifiers := make([]frontend.Variable, len(t.Inputs))
	for i := range t.Inputs {
		firstNullifier := frontend.Variable(0)
		if i > 0 {
			firstNullifier = nullifiers[0]
		}
		treeID, utxoTreeRoot := transaction.SelectTreeSlot(
			api,
			t.Inputs[i].TreeSlot,
			t.Public.TreeIDs,
			t.Public.UtxoTreeRoots,
		)
		inputHashes[i], nullifiers[i] = constrainInput(
			api,
			t.Inputs[i],
			userOwnerHash,
			t.UserNullifierSecret,
			t.Asset,
			utxoTreeRoot,
			t.Public.NullifierTreeRoot,
			treeID,
			t.RingProgramID,
			firstNullifier,
			i,
		)
	}
	transaction.AssertDistinctNullifiers(api, nullifiers)

	sumInputs := frontend.Variable(0)
	for i := range t.Inputs {
		sumInputs = api.Add(sumInputs, t.Inputs[i].Amount)
	}

	outputBlinding := MergeOutputBlinding(api, t.UserNullifierSecret, nullifiers[0])
	outputHash := constrainOutput(
		api,
		t.Output,
		t.Public.OutputHash,
		outputBlinding,
		userOwnerHash,
		t.Asset,
		sumInputs,
		t.RingProgramID,
		t.Public.OutputTreeID,
	)

	addressHashes := make([]frontend.Variable, len(inputHashes))
	for i := range addressHashes {
		addressHashes[i] = frontend.Variable(0)
	}
	privateTxHash := transaction.PrivateTxHashCircuit(
		api,
		inputHashes,
		[]frontend.Variable{outputHash},
		addressHashes,
		t.Public.ExternalDataHash,
		transaction.DerivePrivateTxBlinding(api, nullifiers[0], t.UserNullifierSecret),
	)
	api.AssertIsEqual(privateTxHash, t.Public.PrivateTxHash)

	for i := range nullifiers {
		api.AssertIsEqual(t.Public.Nullifiers[i], nullifiers[i])
	}

	return Derived{
		OwnerPkHash: t.OwnerPkHash,
	}, nil
}
