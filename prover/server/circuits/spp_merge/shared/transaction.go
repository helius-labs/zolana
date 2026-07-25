// Package shared holds the witness building blocks and constraints shared by
// the default and policy-zone SPP merge circuits.
package shared

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/circuits/verifiable-encryption/aes"
	"zolana/prover/circuits/verifiable-encryption/p256"
)

// MergeInputs is the fixed merge shape. Fewer real inputs use dummy slots.
const (
	MergeInputs = 8
	UtxoDomain  = transaction.UtxoDomain
	DummyDomain = transaction.DummyDomain
)

// Input contains the free per-slot merge witness. The circuit supplies the
// shared owner, asset, data hash, and zone program when reconstructing its UTXO.
type Input struct {
	Domain       frontend.Variable
	Amount       frontend.Variable
	Blinding     frontend.Variable
	ZoneDataHash frontend.Variable

	StatePathElements []frontend.Variable
	StatePathIndex    frontend.Variable

	NullifierLowValue        frontend.Variable
	NullifierNextValue       frontend.Variable
	NullifierLowPathElements []frontend.Variable
	NullifierLowPathIndex    frontend.Variable
}

// Output contains the merged output's only free leaf fields. The circuit
// derives its owner, asset, amount, domain, data hash, and zone program.
type Output struct {
	Blinding     frontend.Variable
	ZoneDataHash frontend.Variable
}

// CommonPublicInputs contains the prover-supplied public-input-hash components
// shared by both merge rails. Only the final PublicInputHash is gnark-public;
// Constrain binds every derived component below to its supplied signal.
type CommonPublicInputs struct {
	Nullifiers []frontend.Variable
	OutputHash frontend.Variable

	PrivateTxHash    frontend.Variable
	ExternalDataHash frontend.Variable

	TxViewingPkLo frontend.Variable
	TxViewingPkHi frontend.Variable
	CtHash        frontend.Variable

	UtxoTreeRoots      []frontend.Variable
	NullifierTreeRoots []frontend.Variable
}

// Transaction is the common merge statement over a wrapper-owned witness.
// ZoneProgramID is 0 on the default rail and the zone's public signal on the
// policy-zone rail.
type Transaction struct {
	Inputs []Input
	Output Output

	Asset frontend.Variable

	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable

	TxViewingSk       frontend.Variable
	UserViewingPubkey [65]frontend.Variable

	Public        CommonPublicInputs
	ZoneProgramID frontend.Variable
}

// Derived contains the owner identities a wrapper may publish in its
// public-input-hash preimage.
type Derived struct {
	OwnerPkHash   frontend.Variable
	ViewingPkHash frontend.Variable
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
		Nullifiers:         make([]frontend.Variable, MergeInputs),
		UtxoTreeRoots:      make([]frontend.Variable, MergeInputs),
		NullifierTreeRoots: make([]frontend.Variable, MergeInputs),
	}
}

// Prefix returns the common public-input-hash preimage prefix.
func (p CommonPublicInputs) Prefix(api frontend.API) []frontend.Variable {
	return []frontend.Variable{
		gadget.HashChain(api, p.Nullifiers),
		p.OutputHash,
		gadget.HashChain(api, p.UtxoTreeRoots),
		gadget.HashChain(api, p.NullifierTreeRoots),
		p.PrivateTxHash,
		p.ExternalDataHash,
	}
}

// EncryptionTail returns the public encryption commitment shared by both rails.
func (p CommonPublicInputs) EncryptionTail() []frontend.Variable {
	return []frontend.Variable{p.TxViewingPkLo, p.TxViewingPkHi, p.CtHash}
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
	}{
		{"nullifier", len(t.Public.Nullifiers)},
		{"utxo tree root", len(t.Public.UtxoTreeRoots)},
		{"nullifier tree root", len(t.Public.NullifierTreeRoots)},
	}
	for _, check := range checks {
		if check.got != numInputs {
			return fmt.Errorf(
				"merge: %s count mismatch: got %d want %d",
				check.name,
				check.got,
				numInputs,
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

	inputHashes := make([]frontend.Variable, len(t.Inputs))
	nullifiers := make([]frontend.Variable, len(t.Inputs))
	for i := range t.Inputs {
		inputHashes[i], nullifiers[i] = constrainInput(
			api,
			t.Inputs[i],
			userOwnerHash,
			t.UserNullifierSecret,
			t.Asset,
			t.Public.UtxoTreeRoots[i],
			t.Public.NullifierTreeRoots[i],
			t.ZoneProgramID,
		)
	}
	assertDistinctNullifiers(api, t.Inputs, nullifiers)

	sumInputs := frontend.Variable(0)
	for i := range t.Inputs {
		sumInputs = api.Add(sumInputs, t.Inputs[i].Amount)
	}

	outputHash := constrainOutput(
		api,
		t.Output,
		userOwnerHash,
		t.Asset,
		sumInputs,
		t.ZoneProgramID,
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
	)
	api.AssertIsEqual(privateTxHash, t.Public.PrivateTxHash)

	aesGadget := aes.NewAESGadget(api)
	ctHash, pkLo, pkHi := constrainEncryption(
		api,
		aesGadget,
		t.TxViewingSk,
		t.UserViewingPubkey,
		sumInputs,
		t.Asset,
		t.Output.Blinding,
	)

	viewingPkField, err := transaction.P256PkFieldFromPointCircuit(
		api,
		*p256.ParsePublicKey(api, t.UserViewingPubkey),
	)
	if err != nil {
		return Derived{}, err
	}

	for i := range nullifiers {
		api.AssertIsEqual(t.Public.Nullifiers[i], nullifiers[i])
	}
	api.AssertIsEqual(t.Public.OutputHash, outputHash)
	api.AssertIsEqual(t.Public.TxViewingPkLo, pkLo)
	api.AssertIsEqual(t.Public.TxViewingPkHi, pkHi)
	api.AssertIsEqual(t.Public.CtHash, ctHash)

	return Derived{
		OwnerPkHash:   t.OwnerPkHash,
		ViewingPkHash: viewingPkField,
	}, nil
}

func assertDistinctNullifiers(api frontend.API, inputs []Input, nullifiers []frontend.Variable) {
	for i := range inputs {
		for j := i + 1; j < len(inputs); j++ {
			iReal := api.IsZero(api.Sub(inputs[i].Domain, UtxoDomain))
			jReal := api.IsZero(api.Sub(inputs[j].Domain, UtxoDomain))
			bothReal := api.Mul(iReal, jReal)
			sameNullifier := api.IsZero(api.Sub(nullifiers[i], nullifiers[j]))
			api.AssertIsEqual(api.Mul(bothReal, sameNullifier), 0)
		}
	}
}
