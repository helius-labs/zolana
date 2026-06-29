package transaction

import (
	gadgetlib "zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

type spendEnv struct {
	p256PkField            frontend.Variable
	p256SigValid           frontend.Variable
	requiresP256           bool
	confidential           bool
	p256SigningPkField     frontend.Variable
	zone                   bool
	zoneAuthority          bool
	programID              frontend.Variable
	zoneProgramID          frontend.Variable
	addressTreePubkeyField frontend.Variable
}

// 1. selector (dummy, address, program owned, user owned)
// 2. if dummy utxo fields all zero but blinding
// 3. if address (derived correctly, blinding zero, matches input nullifier)
// 4. if program owned (program_id == owner, program data requires an address, if confidential then input tag == address)
// 5. if user owned (signer check p256, eddsa owned, no program data, if confidential then input tag == owner)
// 6. constrain inclusion of utxo hash if user owned or program owned
// 7. constrain nullifier non inclusion if user owned, program owned or address (address matches nullifier)
func constrainInput(api frontend.API, in Input, nullifierPk frontend.Variable, env spendEnv) (frontend.Variable, frontend.Variable) {
	k := slotSelectors(api, in, env)
	constrainDummyInput(api, k, in)
	constrainAddressSlot(api, k, &in, env)
	constrainProgramOwned(api, k, in, env)
	constrainUserOwned(api, k, in, nullifierPk, env)

	assertEqualWhen(api, k.notDummy, in.Utxo.Domain, UtxoDomain)
	constrainProgramZone(api, k.notDummy, in.Utxo, env.zone, env.zoneAuthority, env.zoneProgramID)
	utxoHash := UtxoHashCircuit(api, in.Utxo)

	constrainInclusion(api, k, in, utxoHash)
	constrainNullifierNonInclusion(api, k, in, utxoHash)

	inputHash := api.Select(in.IsDummy, frontend.Variable(0), utxoHash)
	addressHash := api.Select(k.isAddress, utxoHash, frontend.Variable(0))
	return inputHash, addressHash
}

type slotKind struct {
	isDummy        frontend.Variable
	notDummy       frontend.Variable
	isAddress      frontend.Variable
	spendOrAddress frontend.Variable
	isProgramOwned frontend.Variable
	isUserOwned    frontend.Variable
}

func programOwnedSelector(api frontend.API, owner, programID, notDummy frontend.Variable) frontend.Variable {
	return api.Mul(notDummy, api.IsZero(api.Sub(owner, programID)))
}

func slotSelectors(api frontend.API, in Input, env spendEnv) slotKind {
	api.AssertIsBoolean(in.IsDummy)
	api.AssertIsBoolean(in.IsAddress)
	assertZeroWhen(api, in.IsAddress, api.IsZero(in.IsDummy))
	notDummy := api.Sub(1, in.IsDummy)
	isProgramOwned := programOwnedSelector(api, in.Utxo.Owner, env.programID, notDummy)
	return slotKind{
		isDummy:        in.IsDummy,
		notDummy:       notDummy,
		isAddress:      in.IsAddress,
		spendOrAddress: api.Add(notDummy, in.IsAddress),
		isProgramOwned: isProgramOwned,
		isUserOwned:    api.Sub(notDummy, isProgramOwned),
	}
}

func constrainDummyInput(api frontend.API, k slotKind, in Input) {
	assertZeroWhen(api, k.isDummy, in.Utxo.Amount)
	assertZeroWhen(api, k.isDummy, in.Utxo.Domain)
	assertZeroWhen(api, k.isDummy, in.Utxo.Owner)
	assertZeroWhen(api, k.isDummy, in.Utxo.Asset)
	assertZeroWhen(api, k.isDummy, in.Utxo.Address)
	assertZeroWhen(api, k.isDummy, in.Utxo.ZoneDataHash)
	assertZeroWhen(api, k.isDummy, in.Utxo.DataHash)
	assertZeroWhen(api, k.isDummy, in.Utxo.ZoneProgramID)
	assertZeroWhen(api, k.isDummy, in.NullifierSecret)
}

func constrainAddressSlot(api frontend.API, k slotKind, in *Input, env spendEnv) {
	assertZeroWhen(api, k.isAddress, api.IsZero(env.programID))
	assertZeroWhen(api, k.isAddress, api.IsZero(in.AddressSeed))
	assertZeroWhen(api, k.isAddress, in.Utxo.Blinding)

	derivedAddress := abstractor.Call(api, AddressGadget{
		ProgramId:  env.programID,
		TreePubkey: env.addressTreePubkeyField,
		Seed:       in.AddressSeed,
	})
	in.Utxo.Address = api.Select(k.isAddress, derivedAddress, in.Utxo.Address)
	assertEqualWhen(api, k.isAddress, derivedAddress, in.Nullifier)
}

func constrainProgramOwned(api frontend.API, k slotKind, in Input, env spendEnv) {
	assertZeroWhen(api, k.isProgramOwned, api.IsZero(env.programID))
	assertZeroWhen(api, k.isProgramOwned, in.NullifierSecret)
	requireIdWhenDataSet(api, k.isProgramOwned, in.Utxo.DataHash, in.Utxo.Address)
	if env.confidential {
		assertEqualWhen(api, k.isProgramOwned, in.OwnerPkHash, in.Utxo.Address)
	} else {
		assertEqualWhen(api, k.isProgramOwned, in.OwnerPkHash, env.programID)
	}
}

func constrainUserOwned(api frontend.API, k slotKind, in Input, nullifierPk frontend.Variable, env spendEnv) {
	assertZeroWhen(api, k.isUserOwned, in.Utxo.DataHash)
	assertZeroWhen(api, k.isUserOwned, in.Utxo.Address)

	var isP256, ownerKeyHash frontend.Variable
	if env.confidential {
		isP256 = api.IsZero(api.Sub(in.OwnerPkHash, env.p256SigningPkField))
		ownerKeyHash = in.OwnerPkHash
	} else {
		isP256 = api.IsZero(in.OwnerPkHash)
		ownerKeyHash = api.Select(isP256, env.p256PkField, in.OwnerPkHash)
	}
	if !env.requiresP256 {
		assertZeroWhen(api, k.isUserOwned, isP256)
	}
	ownerHash := abstractor.Call(api, OwnerHashGadget{
		OwnerKeyHash: ownerKeyHash,
		NullifierPk:  nullifierPk,
	})
	assertEqualWhen(api, k.isUserOwned, ownerHash, in.Utxo.Owner)
	assertZeroWhen(api, api.Mul(k.isUserOwned, isP256), api.Sub(1, env.p256SigValid))
}

func constrainInclusion(api frontend.API, k slotKind, in Input, utxoHash frontend.Variable) {
	statePathIndices := api.ToBinary(in.StatePathIndex, StateTreeHeight)
	stateRoot := abstractor.Call(api, gadgetlib.MerkleRootGadget{
		Hash:   utxoHash,
		Index:  statePathIndices,
		Path:   in.StatePathElements,
		Height: StateTreeHeight,
	})
	assertEqualWhen(api, k.notDummy, stateRoot, in.UtxoTreeRoot)
}

func constrainNullifierNonInclusion(api frontend.API, k slotKind, in Input, utxoHash frontend.Variable) {
	nullifier := abstractor.Call(api, NullifierGadget{
		UtxoHash:        utxoHash,
		Blinding:        in.Utxo.Blinding,
		NullifierSecret: in.NullifierSecret,
	})
	assertEqualWhen(api, k.notDummy, nullifier, in.Nullifier)

	lowLeafHash := gadgetlib.IndexedLeafHash(api, in.NullifierLowValue, in.NullifierNextValue)
	nfPathIndices := api.ToBinary(in.NullifierLowPathIndex, NullifierTreeHeight)
	nfRoot := abstractor.Call(api, gadgetlib.MerkleRootGadget{
		Hash:   lowLeafHash,
		Index:  nfPathIndices,
		Path:   in.NullifierLowPathElements,
		Height: NullifierTreeHeight,
	})
	assertEqualWhen(api, k.spendOrAddress, nfRoot, in.NullifierTreeRoot)
	assertStrictlyOrdered(api, api.Sub(1, k.spendOrAddress), in.NullifierLowValue, in.Nullifier, in.NullifierNextValue)
}

func constrainProgramZone(api frontend.API, notDummy frontend.Variable, u UtxoCircuitFields, zone, strictZone bool, zoneProgramID frontend.Variable) {
	if zone {
		if strictZone { // mode with zone authority every utxo must be in the zone.
			assertEqualWhen(api, notDummy, u.ZoneProgramID, zoneProgramID)
		} else {
			// transact utxos can be in the zone.
			// if yes zone program id must match.
			bindIfSet(api, notDummy, u.ZoneProgramID, zoneProgramID)
		}
		requireIdWhenDataSet(api, notDummy, u.ZoneDataHash, u.ZoneProgramID)
	} else {
		// Not in a zone must be 0
		assertZeroWhen(api, notDummy, u.ZoneDataHash)
		assertZeroWhen(api, notDummy, u.ZoneProgramID)
	}
}

func bindIfSet(api frontend.API, notDummy, field, public frontend.Variable) {
	isSet := api.Sub(1, api.IsZero(field))
	assertEqualWhen(api, api.Mul(notDummy, isSet), field, public)
}

func requireIdWhenDataSet(api frontend.API, notDummy, dataHash, id frontend.Variable) {
	dataIsSet := api.Sub(1, api.IsZero(dataHash))
	assertZeroWhen(api, api.Mul(notDummy, dataIsSet), api.IsZero(id))
}

func (c *Circuit) assertDistinctNullifiers(api frontend.API) {
	for i := range c.Inputs {
		for j := i + 1; j < len(c.Inputs); j++ {
			api.AssertIsDifferent(c.Inputs[i].Nullifier, c.Inputs[j].Nullifier)
		}
	}
}

type NullifierPkGadget struct {
	NullifierSecret frontend.Variable
}

func (gadget NullifierPkGadget) DefineGadget(api frontend.API) interface{} {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{gadget.NullifierSecret})
}

type NullifierGadget struct {
	UtxoHash        frontend.Variable
	Blinding        frontend.Variable
	NullifierSecret frontend.Variable
}

func (gadget NullifierGadget) DefineGadget(api frontend.API) interface{} {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{
		gadget.UtxoHash,
		gadget.Blinding,
		gadget.NullifierSecret,
	})
}

type AssertStrictlyOrdered struct {
	IsDummy frontend.Variable
	Lo      frontend.Variable
	Mid     frontend.Variable
	Hi      frontend.Variable
}

func (gadget AssertStrictlyOrdered) DefineGadget(api frontend.API) interface{} {
	lo := api.Select(gadget.IsDummy, frontend.Variable(0), gadget.Lo)
	mid := api.Select(gadget.IsDummy, frontend.Variable(1), gadget.Mid)
	hi := api.Select(gadget.IsDummy, frontend.Variable(2), gadget.Hi)
	loLimbs := gadgetlib.CanonicalLimbs(api, lo)
	midLimbs := gadgetlib.CanonicalLimbs(api, mid)
	hiLimbs := gadgetlib.CanonicalLimbs(api, hi)
	api.AssertIsEqual(gadgetlib.IsLessLimbs(api, loLimbs, midLimbs), 1)
	api.AssertIsEqual(gadgetlib.IsLessLimbs(api, midLimbs, hiLimbs), 1)
	return []frontend.Variable{}
}

func assertStrictlyOrdered(api frontend.API, isDummy, lo, mid, hi frontend.Variable) {
	abstractor.CallVoid(api, AssertStrictlyOrdered{IsDummy: isDummy, Lo: lo, Mid: mid, Hi: hi})
}
