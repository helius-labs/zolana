package merge

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction/shared"
)

// constrainInput verifies one merged input: cleanliness, state-tree inclusion,
// nullifier derivation under the shared nullifier secret, and nullifier-tree
// non-inclusion. Ownership and asset uniformity are not asserted directly: the
// leaf is reconstructed from the shared user_owner_hash and asset, so a real
// input whose committed leaf disagrees fails inclusion. Every check is gated on
// the slot being real; a dummy slot skips them. Returns the input's UTXO hash (0
// for a dummy) for the private-transaction-hash chain and its nullifier.
func constrainInput(api frontend.API, in Input, userOwnerHash, userNullifierSecret, asset frontend.Variable, zone bool, zoneProgramID frontend.Variable) (frontend.Variable, frontend.Variable) {
	// Slot type is decoded from the domain, matching spp_transaction: a real
	// input carries UtxoDomain, a padding slot carries DummyDomain. The partition
	// assert both pins the domain to one of the two values and defines notDummy.
	isDummy := api.IsZero(api.Sub(in.Domain, DummyDomain))
	isUtxo := api.IsZero(api.Sub(in.Domain, UtxoDomain))
	api.AssertIsEqual(api.Add(isUtxo, isDummy), 1)
	notDummy := isUtxo

	// Dummy slots are inert (zero amount); their public columns stay unpinned so
	// a dummy is indistinguishable from a real input and hides the real arity.
	assertZeroWhen(api, isDummy, in.Amount)

	// Range-check the amount to 64 bits so value conservation cannot wrap the
	// field. Dummies carry amount 0, which trivially fits. This makes the merge
	// proof self-contained rather than relying on upstream creation circuits to
	// keep every tree UTXO u64-bounded.
	abstractor.CallVoid(api, transaction.RangeCheck64{Value: in.Amount})

	// Default rail: an input carries no zone data. The zone rail leaves
	// ZoneDataHash free (part of the committed leaf).
	if !zone {
		assertZeroWhen(api, notDummy, in.ZoneDataHash)
	}

	// Reconstruct the leaf. A real slot binds the shared owner, asset, nullifier
	// secret, and zone program; a dummy slot zeroes all of them so its leaf and
	// derived nullifier match the padding leaf the client builds (domain-tagged,
	// otherwise empty, hashed under a zero nullifier secret). That keeps the
	// nullifier the client chains into the public input reproducible in-circuit.
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
	utxoHash := transaction.UtxoHashCircuit(api, utxo)

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
	// secret. Together with the owner-hash binding this pins nullifier_secret. It
	// is assembled here rather than witnessed; the caller chains it into the public
	// input. A dummy slot's nullifier is pseudorandom via its free blinding, so it
	// stays indistinguishable from a real one and hides the real arity.
	nullifier := abstractor.Call(api, transaction.NullifierGadget{
		UtxoHash:        utxoHash,
		Blinding:        in.Blinding,
		NullifierSecret: nullifierSecret,
	})

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
	// Dummy entries are remapped to the trivially ordered 0 < 1 < 2.
	abstractor.CallVoid(api, transaction.AssertStrictlyOrdered{
		Lo:  api.Select(isDummy, frontend.Variable(0), in.NullifierLowValue),
		Mid: api.Select(isDummy, frontend.Variable(1), nullifier),
		Hi:  api.Select(isDummy, frontend.Variable(2), in.NullifierNextValue),
	})

	return api.Select(isDummy, frontend.Variable(0), utxoHash), nullifier
}

// assertEqualWhen constrains a == b only when cond == 1.
func assertEqualWhen(api frontend.API, cond, a, b frontend.Variable) {
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: cond, A: a, B: b})
}

// assertZeroWhen constrains v == 0 only when cond == 1.
func assertZeroWhen(api frontend.API, cond, v frontend.Variable) {
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: cond, V: v})
}
