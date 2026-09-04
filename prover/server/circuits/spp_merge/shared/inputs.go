package shared

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction/shared"
)

// Checks:
// UTXO or dummy:
// - nullifier non inclusion
// 1. UTXO:
//   - inclusion
//   - UTXOs with data hash cannot be merged
//
// 2. Dummy
// - all UTXO fields and nullifier secret are zero
// - nullifier is derived deterministically
func constrainInput(
	api frontend.API,
	in Input,
	userOwnerHash,
	userNullifierSecret,
	asset,
	utxoTreeRoot,
	nullifierTreeRoot,
	treeID,
	ringProgramID,
	firstNullifier frontend.Variable,
	slotIndex int,
) (frontend.Variable, frontend.Variable) {
	isDummy := api.IsZero(api.Sub(in.Domain, DummyDomain))
	isUtxo := api.IsZero(api.Sub(in.Domain, UtxoDomain))
	api.AssertIsEqual(api.Add(isUtxo, isDummy), 1)
	notDummy := isUtxo
	abstractor.CallVoid(api, transaction.RangeCheck64{Value: in.Amount})

	leafOwner := api.Select(isDummy, frontend.Variable(0), userOwnerHash)
	leafAsset := api.Select(isDummy, frontend.Variable(0), asset)
	leafRingProgramID := api.Select(isDummy, frontend.Variable(0), ringProgramID)
	nullifierSecret := api.Select(isDummy, frontend.Variable(0), userNullifierSecret)
	utxo := transaction.UtxoCircuitFields{
		Domain:        in.Domain,
		Owner:         leafOwner,
		Asset:         leafAsset,
		Amount:        in.Amount,
		Blinding:      in.Blinding,
		DataHash:      frontend.Variable(0),
		RingDataHash:  in.RingDataHash,
		RingProgramID: leafRingProgramID,
	}
	transaction.AssertWhen(api, isDummy, utxo.CheckDummy(api))
	utxoHash := transaction.UtxoHashCircuit(api, utxo, treeID)

	// Inclusion: utxoHash is a leaf of the state tree at UtxoTreeRoot.
	statePathIndices := api.ToBinary(in.StatePathIndex, transaction.StateTreeHeight)
	stateRoot := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   utxoHash,
		Index:  statePathIndices,
		Path:   in.StatePathElements,
		Height: transaction.StateTreeHeight,
	})
	assertEqualWhen(api, notDummy, stateRoot, utxoTreeRoot)

	nullifier := abstractor.Call(api, transaction.NullifierGadget{
		UtxoHash:        utxoHash,
		Blinding:        in.Blinding,
		NullifierSecret: nullifierSecret,
	})
	nullifier = api.Select(
		isDummy,
		MergeDummyNullifier(api, userNullifierSecret, firstNullifier, slotIndex),
		nullifier,
	)

	// Non-inclusion: the low leaf is in the nullifier tree and brackets the
	// nullifier (NullifierLowValue < Nullifier < NullifierNextValue).
	lowLeafHash := gadget.IndexedLeafHash(api, in.NullifierLowValue, in.NullifierNextValue)
	nfPathIndices := api.ToBinary(in.NullifierLowPathIndex, transaction.NullifierTreeHeight)
	nfRoot := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   lowLeafHash,
		Index:  nfPathIndices,
		Path:   in.NullifierLowPathElements,
		Height: transaction.NullifierTreeHeight,
	})

	api.AssertIsEqual(nfRoot, nullifierTreeRoot)
	abstractor.CallVoid(api, transaction.AssertStrictlyOrdered{
		Lo:  in.NullifierLowValue,
		Mid: nullifier,
		Hi:  in.NullifierNextValue,
	})

	return api.Select(isDummy, frontend.Variable(0), utxoHash), nullifier
}

// assertEqualWhen constrains a == b only when cond == 1.
func assertEqualWhen(api frontend.API, cond, a, b frontend.Variable) {
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: cond, A: a, B: b})
}
