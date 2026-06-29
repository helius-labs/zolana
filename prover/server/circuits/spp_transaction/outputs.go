package transaction

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// outputKind holds the per-output selector flags. A real output (IsDummy == 0)
// is either program-owned (owner == program_id) or user-owned; a dummy output is
// neither.
type outputKind struct {
	isDummy        frontend.Variable
	notDummy       frontend.Variable
	isProgramOwned frontend.Variable
	userOwnedReal  frontend.Variable
}

// outputSelectors derives the output's kind flags from IsDummy and the public
// program_id.
func outputSelectors(api frontend.API, out Output, programID frontend.Variable) outputKind {
	api.AssertIsBoolean(out.IsDummy)
	notDummy := api.Sub(1, out.IsDummy)
	isProgramOwned := programOwnedSelector(api, out.Utxo.Owner, programID, notDummy)
	return outputKind{
		isDummy:        out.IsDummy,
		notDummy:       notDummy,
		isProgramOwned: isProgramOwned,
		userOwnedReal:  api.Sub(notDummy, isProgramOwned),
	}
}

// 1. selector(dummy, program owned, user owned)
// 2. if dummy utxo fields all zero but blinding
// 3. if program owned (evn.programId == owner, must have an address, address must be a nullifier that is an address or an existing address of an input utxo, if confidential then input tag == address)
// 4. utxo hash well formed
func constrainOutput(api frontend.API, out Output, confidential, zone, zoneAuthority bool, programID, zoneProgramID frontend.Variable) frontend.Variable {
	k := outputSelectors(api, out, programID)
	constrainDummyOutput(api, k, out)
	constrainRealDomain(api, k, out)
	constrainUserOwnedOutput(api, k, out)
	constrainProgramZone(api, k.notDummy, out.Utxo, zone, zoneAuthority, zoneProgramID)
	utxoHash := UtxoHashCircuit(api, out.Utxo)
	api.AssertIsEqual(utxoHash, out.Hash)
	if confidential {
		constrainConfidentialOwnerTag(api, k, out)
	}
	return api.Select(out.IsDummy, frontend.Variable(0), utxoHash)
}

// constrainDummyOutput pins a dummy output to the canonical empty UTXO: every
// field zero except blinding (see spec Empty UTXO). Asset is the lone exception
// at the circuit layer: the empty UTXO's asset is the zero address, which the
// Asset field carries Poseidon-encoded, so it is pinned to SolAsset() (Poseidon(0,0))
// rather than 0.
func constrainDummyOutput(api frontend.API, k outputKind, out Output) {
	assertZeroWhen(api, k.isDummy, out.Utxo.Domain)
	assertZeroWhen(api, k.isDummy, out.Utxo.Owner)
	assertEqualWhen(api, k.isDummy, out.Utxo.Asset, SolAsset())
	assertZeroWhen(api, k.isDummy, out.Utxo.Amount)
	assertZeroWhen(api, k.isDummy, out.Utxo.DataHash)
	assertZeroWhen(api, k.isDummy, out.Utxo.Address)
	assertZeroWhen(api, k.isDummy, out.Utxo.ZoneDataHash)
	assertZeroWhen(api, k.isDummy, out.Utxo.ZoneProgramID)
}

// constrainRealDomain pins every real output's domain tag.
func constrainRealDomain(api frontend.API, k outputKind, out Output) {
	assertEqualWhen(api, k.notDummy, out.Utxo.Domain, UtxoDomain)
}

// constrainUserOwnedOutput forbids program data and a persistent address on a
// user-owned output; both live only on program-owned UTXOs.
func constrainUserOwnedOutput(api frontend.API, k outputKind, out Output) {
	assertZeroWhen(api, k.userOwnedReal, out.Utxo.DataHash)
	assertZeroWhen(api, k.userOwnedReal, out.Utxo.Address)
}

// constrainOutputCommitment recomputes the UTXO hash and binds it to out.Hash.
func constrainOutputCommitment(api frontend.API, out Output) frontend.Variable {
	utxoHash := UtxoHashCircuit(api, out.Utxo)
	api.AssertIsEqual(utxoHash, out.Hash)
	return utxoHash
}

// constrainConfidentialOwnerTag binds the public owner tag to the output. A
// user-owned output's tag recomputes its owner_hash; a program-owned output's tag
// carries its address (committed in program_hash) rather than an owner_hash.
func constrainConfidentialOwnerTag(api frontend.API, k outputKind, out Output) {
	ownerHash := abstractor.Call(api, OwnerHashGadget{
		OwnerKeyHash: out.OwnerPkHash,
		NullifierPk:  out.NullifierPk,
	})
	assertEqualWhen(api, k.userOwnedReal, ownerHash, out.Utxo.Owner)
	assertEqualWhen(api, k.isProgramOwned, out.OwnerPkHash, out.Utxo.Address)
}
