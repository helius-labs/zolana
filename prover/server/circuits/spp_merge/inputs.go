package merge

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction"
)

// constrainInput verifies one merged input: cleanliness, ownership and asset
// uniformity, state-tree inclusion, nullifier derivation under the shared
// nullifier secret, and nullifier-tree non-inclusion. Every check is gated on
// the slot being real; a dummy slot skips them. It returns the input's UTXO
// hash (0 for a dummy) for the private-transaction-hash chain.
func constrainInput(api frontend.API, in Input, userOwnerHash, userNullifierSecret, outputAsset frontend.Variable, zone bool, zoneProgramID frontend.Variable) frontend.Variable {
	api.AssertIsBoolean(in.IsDummy)
	notDummy := api.Sub(1, in.IsDummy)

	// Dummy slots are inert (zero amount); their public columns stay unpinned so
	// a dummy is indistinguishable from a real input and hides the real arity.
	assertZeroWhen(api, in.IsDummy, in.Utxo.Amount)
	assertEqualWhen(api, notDummy, in.Utxo.Domain, UtxoDomain)

	// Range-check the amount to 64 bits so value conservation cannot wrap the
	// field. Dummies carry amount 0, which trivially fits. This makes the merge
	// proof self-contained rather than relying on upstream creation circuits to
	// keep every tree UTXO u64-bounded.
	abstractor.CallVoid(api, transaction.RangeCheck64{Value: in.Utxo.Amount})

	assertZeroWhen(api, notDummy, in.Utxo.DataHash)
	if zone {
		assertEqualWhen(api, notDummy, in.Utxo.ZoneProgramID, zoneProgramID)
	} else {
		assertZeroWhen(api, notDummy, in.Utxo.ZoneDataHash)
		assertZeroWhen(api, notDummy, in.Utxo.ZoneProgramID)
	}

	// Ownership and asset uniformity: every real input shares user_owner_hash and
	// the output's asset.
	assertEqualWhen(api, notDummy, in.Utxo.Owner, userOwnerHash)
	assertEqualWhen(api, notDummy, in.Utxo.Asset, outputAsset)

	utxoHash := transaction.UtxoHashCircuit(api, in.Utxo)

	// Inclusion: utxoHash is a leaf of the state tree at UtxoTreeRoot.
	statePathIndices := api.ToBinary(in.StatePathIndex, transaction.StateTreeHeight)
	stateRoot := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   utxoHash,
		Index:  statePathIndices,
		Path:   in.StatePathElements,
		Height: transaction.StateTreeHeight,
	})
	assertEqualWhen(api, notDummy, stateRoot, in.UtxoTreeRoot)

	// Nullifier: Poseidon over the UTXO hash, blinding, and the shared nullifier
	// secret. Together with the owner-hash binding this pins nullifier_secret.
	nullifier := abstractor.Call(api, transaction.NullifierGadget{
		UtxoHash:        utxoHash,
		Blinding:        in.Utxo.Blinding,
		NullifierSecret: userNullifierSecret,
	})
	assertEqualWhen(api, notDummy, nullifier, in.Nullifier)

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
	assertEqualWhen(api, notDummy, nfRoot, in.NullifierTreeRoot)
	abstractor.CallVoid(api, transaction.AssertStrictlyOrdered{
		IsDummy: in.IsDummy,
		Lo:      in.NullifierLowValue,
		Mid:     in.Nullifier,
		Hi:      in.NullifierNextValue,
	})

	return api.Select(in.IsDummy, frontend.Variable(0), utxoHash)
}

// assertEqualWhen constrains a == b only when cond == 1.
func assertEqualWhen(api frontend.API, cond, a, b frontend.Variable) {
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: cond, A: a, B: b})
}

// assertZeroWhen constrains v == 0 only when cond == 1.
func assertZeroWhen(api frontend.API, cond, v frontend.Variable) {
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: cond, V: v})
}
