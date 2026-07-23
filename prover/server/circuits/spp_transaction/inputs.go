package transaction

import (
	gadgetlib "zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// spendEnv holds the per-proof values shared by every input-spend check: the
// one witnessed P256 key and the one signature over private_tx_hash that
// authorize all P256-owned inputs.
type spendEnv struct {
	p256PkField  frontend.Variable
	p256SigValid frontend.Variable
	// requiresP256 is false for the Solana-only circuit variant, which omits the
	// P256 gadget and must therefore reject P256-owned inputs.
	requiresP256 bool
	// isCustomZone routes ownership by equality to p256SigningPkField (the shared
	// P256 key's pk_field) instead of the 0 sentinel, so P256 input owners are public.
	isCustomZone       bool
	p256SigningPkField frontend.Variable
	zone               bool
	zoneAuthority      bool
	zoneProgramID      frontend.Variable
}

func constrainProgramZone(api frontend.API, notDummy frontend.Variable, u UtxoCircuitFields, zone, strictZone bool, zoneProgramID frontend.Variable) {
	if zone {
		if strictZone {
			assertEqualWhen(api, notDummy, u.ZoneProgramID, zoneProgramID)
		} else {
			bindIfSet(api, notDummy, u.ZoneProgramID, zoneProgramID)
		}
		requireIdWhenDataSet(api, notDummy, u.ZoneDataHash, u.ZoneProgramID)
	} else {
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

func (c *Circuit) assertInputs(api frontend.API, env spendEnv) ([]frontend.Variable, []frontend.Variable) {
	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	addressHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i := 0; i < c.Shape.NInputs; i++ {
		inputHashes[i], addressHashes[i] = constrainInput(api, c.Inputs[i], env)
	}
	return inputHashes, addressHashes
}

// TODO: add wrapper functions constrainZoneInput, constrainDefaultZoneInput, constrainEddsaOnlyInput, constrainP256Input
func constrainInput(api frontend.API, in Input, env spendEnv) (frontend.Variable, frontend.Variable) {
	api.AssertIsBoolean(in.IsDummy)
	nullifierPk := abstractor.Call(api, NullifierPkGadget{
		NullifierSecret: in.NullifierSecret,
	})
	notDummy := api.Sub(1, in.IsDummy)
	// TODO: restructure into methods checkAddress, checkDummy, checkSpendable
	dataIsSet := api.Sub(1, api.IsZero(in.Utxo.DataHash))
	isAddress := api.Mul(in.IsDummy, dataIsSet)
	isDummyNotAddress := api.Sub(in.IsDummy, isAddress)
	realOrAddress := api.Sub(1, isDummyNotAddress)

	assertZeroWhen(api, in.IsDummy, in.Utxo.Amount)
	assertZeroWhen(api, isDummyNotAddress, in.Utxo.Owner)

	assertZeroWhen(api, isAddress, in.Utxo.Blinding)
	assertZeroWhen(api, isAddress, in.Utxo.Asset)
	assertZeroWhen(api, isAddress, in.Utxo.ZoneDataHash)
	assertZeroWhen(api, isAddress, in.Utxo.ZoneProgramID)

	assertEqualWhen(api, realOrAddress, in.Utxo.Domain, UtxoDomain)
	constrainProgramZone(api, notDummy, in.Utxo, env.zone, env.zoneAuthority, env.zoneProgramID)

	utxoHash := UtxoHashCircuit(api, in.Utxo)

	// Inclusion: utxoHash is a leaf of the state tree at UtxoTreeRoot.
	statePathIndices := api.ToBinary(in.StatePathIndex, StateTreeHeight)
	stateRoot := abstractor.Call(api, gadgetlib.MerkleRootGadget{
		Hash:   utxoHash,
		Index:  statePathIndices,
		Path:   in.StatePathElements,
		Height: StateTreeHeight,
	})
	assertEqualWhen(api, notDummy, stateRoot, in.UtxoTreeRoot)

	// Owner check: select the input's path and bind the owner. Anonymous routes on
	// the 0 sentinel — 0 binds to the shared P256 key (substituted via Select),
	// non-zero to the entry. Confidential routes by equality to the public
	// p256SigningPkField, so a P256 owner's pk_field is public in OwnerPkHash and is
	// already the owner key — no substitution, so the Select is omitted.
	var isP256, ownerKeyHash frontend.Variable
	if env.isCustomZone {
		isP256 = api.IsZero(api.Sub(in.OwnerPkHash, env.p256SigningPkField))
		ownerKeyHash = in.OwnerPkHash
	} else {
		isP256 = api.IsZero(in.OwnerPkHash)
		ownerKeyHash = api.Select(isP256, env.p256PkField, in.OwnerPkHash)
	}
	if !env.requiresP256 {
		assertZeroWhen(api, realOrAddress, isP256)
	}
	ownerHash := abstractor.Call(api, OwnerHashGadget{
		OwnerKeyHash: ownerKeyHash,
		NullifierPk:  nullifierPk,
	})
	assertEqualWhen(api, realOrAddress, ownerHash, in.Utxo.Owner)
	assertZeroWhen(api, api.Mul(realOrAddress, isP256), api.Sub(1, env.p256SigValid))

	nullifier := abstractor.Call(api, NullifierGadget{
		UtxoHash:        utxoHash,
		Blinding:        in.Utxo.Blinding,
		NullifierSecret: in.NullifierSecret,
	})
	assertEqualWhen(api, realOrAddress, nullifier, in.Nullifier)

	// Non-inclusion: the low leaf is in the nullifier tree and brackets the
	// nullifier (NullifierLowValue < Nullifier < NullifierNextValue).
	lowLeafHash := gadgetlib.IndexedLeafHash(api, in.NullifierLowValue, in.NullifierNextValue)
	nfPathIndices := api.ToBinary(in.NullifierLowPathIndex, NullifierTreeHeight)
	nfRoot := abstractor.Call(api, gadgetlib.MerkleRootGadget{
		Hash:   lowLeafHash,
		Index:  nfPathIndices,
		Path:   in.NullifierLowPathElements,
		Height: NullifierTreeHeight,
	})
	assertEqualWhen(api, notDummy, nfRoot, in.NullifierTreeRoot)
	assertStrictlyOrdered(api, in.IsDummy, in.NullifierLowValue, in.Nullifier, in.NullifierNextValue)

	inputHash := api.Select(in.IsDummy, frontend.Variable(0), utxoHash)
	addressHash := api.Select(isAddress, utxoHash, frontend.Variable(0))
	return inputHash, addressHash
}

func (c *Circuit) assertDistinctNullifiers(api frontend.API) {
	for i := range c.Inputs {
		for j := i + 1; j < len(c.Inputs); j++ {
			api.AssertIsDifferent(c.Inputs[i].Nullifier, c.Inputs[j].Nullifier)
		}
	}
}

// NullifierPkGadget derives the public nullifier key from the secret (step 3.1).
type NullifierPkGadget struct {
	NullifierSecret frontend.Variable
}

func (gadget NullifierPkGadget) DefineGadget(api frontend.API) interface{} {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{gadget.NullifierSecret})
}

// NullifierGadget derives a nullifier from the UTXO hash, its blinding, and the
// spender's nullifier secret (step 3.4).
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

// AssertStrictlyOrdered constrains lo < mid < hi for a real entry, comparing
// full field values (see gadget.IsLessLimbs) — the nullifier tree's
// indexed-value domain spans the whole field. Dummy entries (IsDummy == 1) are
// remapped to 0 < 1 < 2, so the check always passes for them. Backs the
// non-inclusion check in step 3.6.
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
