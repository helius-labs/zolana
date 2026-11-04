package shared

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// ConstrainSeeded keys input nullifiers on UserNullifierSecret and derived values
// on seed, since a note opening reveals a zero secret.
func (t Transaction) ConstrainSeeded(api frontend.API, seed frontend.Variable) Derived {
	userOwnerHash := gadget.PoseidonHash(
		api,
		[]frontend.Variable{t.OwnerPkHash, t.UserNullifierPk},
	)
	asset := gadget.HashChain(api, t.MintChunks[:])

	api.AssertIsEqual(
		t.UserNullifierPk,
		gadget.PoseidonHash(api, []frontend.Variable{t.UserNullifierSecret}),
	)
	api.AssertIsBoolean(t.Public.AllowDummyInputs)
	isCompact := transaction.CompactSlots(api, t.Public.Nullifiers)
	for i := range t.Inputs {
		isDummy := api.IsZero(api.Sub(t.Inputs[i].Domain, DummyDomain))
		api.AssertIsEqual(
			api.Mul(api.Sub(1, t.Public.AllowDummyInputs), api.Sub(isDummy, isCompact[i])),
			0,
		)
	}

	// Slot zero seeds the output, so a dummy there would make the derivations
	// repeat across merges.
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
		inputHashes[i], nullifiers[i] = constrainSeededInput(api, t.Inputs[i], ctx, seed, tree, i, isCompact[i])
		ctx.FirstNullifier = nullifiers[0]
	}
	transaction.AssertDistinctNullifiers(api, nullifiers, isCompact)

	sumInputs := frontend.Variable(0)
	for i := range t.Inputs {
		sumInputs = api.Add(sumInputs, t.Inputs[i].Amount)
	}

	outputHash := constrainOutput(
		api,
		t.Output,
		t.Public.OutputHash,
		MergeOutputBlinding(api, seed, nullifiers[0]),
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
		transaction.DerivePrivateTxBlinding(api, nullifiers[0], seed),
	)
	api.AssertIsEqual(privateTxHash, t.Public.PrivateTxHash)

	for i := range nullifiers {
		api.AssertIsEqual(t.Public.Nullifiers[i], nullifiers[i])
	}

	return Derived{
		OutputAmount:   sumInputs,
		FirstNullifier: nullifiers[0],
	}
}

func constrainSeededInput(
	api frontend.API,
	in Input,
	ctx mergeInputContext,
	seed frontend.Variable,
	tree transaction.TreeSlot,
	slotIndex int,
	isCompact frontend.Variable,
) (frontend.Variable, frontend.Variable) {
	isDummy := api.IsZero(api.Sub(in.Domain, DummyDomain))
	isUtxo := api.IsZero(api.Sub(in.Domain, UtxoDomain))
	api.AssertIsEqual(api.Add(isUtxo, isDummy), 1)
	transaction.AssertWhen(api, isCompact, isDummy)
	abstractor.CallVoid(api, transaction.RangeCheck64{Value: in.Amount})

	utxo := transaction.UtxoCircuitFields{
		Domain:        in.Domain,
		Owner:         api.Select(isDummy, frontend.Variable(0), ctx.OwnerHash),
		Asset:         api.Select(isDummy, frontend.Variable(0), ctx.Asset),
		Amount:        in.Amount,
		Blinding:      in.Blinding,
		DataHash:      frontend.Variable(0),
		RingDataHash:  in.RingDataHash,
		RingProgramID: api.Select(isDummy, frontend.Variable(0), ctx.RingProgramID),
	}
	transaction.AssertWhen(api, isDummy, utxo.CheckDummy(api))
	utxoHash := transaction.UtxoHashCircuit(api, utxo, tree.ID)

	stateRoot := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   utxoHash,
		Index:  api.ToBinary(in.StatePathIndex, transaction.StateTreeHeight),
		Path:   in.StatePathElements,
		Height: transaction.StateTreeHeight,
	})
	assertEqualWhen(api, isUtxo, stateRoot, tree.UtxoRoot)

	nullifier := abstractor.Call(api, transaction.NullifierGadget{
		UtxoHash:        utxoHash,
		Blinding:        in.Blinding,
		NullifierSecret: api.Select(isDummy, frontend.Variable(0), ctx.NullifierSecret),
	})
	nullifier = api.Select(
		isDummy,
		MergeDummyNullifier(api, seed, ctx.FirstNullifier, slotIndex),
		nullifier,
	)

	nullifierRoot := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   gadget.IndexedLeafHash(api, in.NullifierLowValue, in.NullifierNextValue),
		Index:  api.ToBinary(in.NullifierLowPathIndex, transaction.NullifierTreeHeight),
		Path:   in.NullifierLowPathElements,
		Height: transaction.NullifierTreeHeight,
	})
	api.AssertIsEqual(nullifierRoot, tree.NullifierRoot)
	abstractor.CallVoid(api, transaction.AssertStrictlyOrdered{
		Lo:  in.NullifierLowValue,
		Mid: nullifier,
		Hi:  in.NullifierNextValue,
	})

	return api.Select(isDummy, frontend.Variable(0), utxoHash), api.Select(isCompact, frontend.Variable(0), nullifier)
}
