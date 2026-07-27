package shared

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction/shared"
)

func constrainInput(
	api frontend.API,
	in Input,
	userOwnerHash,
	userNullifierSecret,
	asset,
	utxoTreeRoot,
	nullifierTreeRoot,
	zoneProgramID,
	firstInputBlinding,
	firstNullifier frontend.Variable,
	slotIndex int,
) (frontend.Variable, frontend.Variable) {
	isDummy := api.IsZero(api.Sub(in.Domain, DummyDomain))
	isUtxo := api.IsZero(api.Sub(in.Domain, UtxoDomain))
	api.AssertIsEqual(api.Add(isUtxo, isDummy), 1)
	notDummy := isUtxo
‚
	abstractor.CallVoid(api, transaction.RangeCheck64{Value: in.Amount})

	// Reconstruct the leaf. A real slot binds the shared owner, asset, nullifier
	// secret, and zone program; a dummy slot zeroes those shared fields.
	// DataHash is always 0.
	leafOwner := api.Select(isDummy, frontend.Variable(0), userOwnerHash)
	leafAsset := api.Select(isDummy, frontend.Variable(0), asset)
	leafZoneProgramID := api.Select(isDummy, frontend.Variable(0), zoneProgramID)
	nullifierSecret := api.Select(isDummy, frontend.Variable(0), userNullifierSecret)
	utxo := transaction.UtxoCircuitFields{
		Domain:        in.Domain,
		Owner:         leafOwner,
		Asset:         leafAsset,
		Amount:        in.Amount,
		Blinding:      in.Blinding,
		DataHash:      frontend.Variable(0),
		ZoneDataHash:  in.ZoneDataHash,
		ZoneProgramID: leafZoneProgramID,
	}
	// Reuse the canonical transaction dummy rule: every dummy UTXO field except
	// domain and blinding is zero. In particular, private dummy zone data cannot
	// carry an otherwise unconstrained value.
	transaction.AssertWhen(api, isDummy, utxo.CheckDummy(api))
	utxoHash := transaction.UtxoHashCircuit(api, utxo)

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
		MergeDummyNullifier(api, firstInputBlinding, firstNullifier, slotIndex),
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

	abstractor.CallVoid(api, gadget.AssertEqualWhen{
		Cond: 1,
		A:    nfRoot,
		B:    nullifierTreeRoot,
	})
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
