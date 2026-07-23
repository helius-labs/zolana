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
//
// An input slot is one of three kinds: a real spend (IsDummy == 0), an address
// creation (IsDummy == 1 with a data hash), or padding (IsDummy == 1 without).
// checkDummy/checkAddress pin the fields the respective kind must not carry;
// checkSpendable runs the spend checks, degraded per kind by its gate flags.
func constrainInput(api frontend.API, in Input, env spendEnv) (frontend.Variable, frontend.Variable) {
	api.AssertIsBoolean(in.IsDummy)
	dataIsSet := api.Sub(1, api.IsZero(in.Utxo.DataHash))
	isAddress := api.Mul(in.IsDummy, dataIsSet)
	isDummyNotAddress := api.Sub(in.IsDummy, isAddress)
	realOrAddress := api.Sub(1, isDummyNotAddress)

	in.checkDummy(api, isDummyNotAddress)
	in.checkAddress(api, isAddress)
	utxoHash := in.checkSpendable(api, env, realOrAddress)

	inputHash := api.Select(in.IsDummy, frontend.Variable(0), utxoHash)
	addressHash := api.Select(isAddress, utxoHash, frontend.Variable(0))
	return inputHash, addressHash
}

// checkDummy: no dummy (address or padding) moves value, and padding carries no
// owner either.
func (in Input) checkDummy(api frontend.API, isDummyNotAddress frontend.Variable) {
	assertZeroWhen(api, in.IsDummy, in.Utxo.Amount)
	assertZeroWhen(api, isDummyNotAddress, in.Utxo.Owner)
}

// checkAddress: an address entry is only owner + data hash; the value and zone
// fields must be empty.
func (in Input) checkAddress(api frontend.API, isAddress frontend.Variable) {
	assertZeroWhen(api, isAddress, in.Utxo.Blinding)
	assertZeroWhen(api, isAddress, in.Utxo.Asset)
	assertZeroWhen(api, isAddress, in.Utxo.ZoneDataHash)
	assertZeroWhen(api, isAddress, in.Utxo.ZoneProgramID)
}

// checkSpendable runs the spend checks and returns the input's UTXO hash. The
// gates degrade per kind: a real spend (notDummy and realOrAddress both 1) gets
// every check, an address (realOrAddress 1) skips the tree checks but still
// binds domain, owner, and nullifier, and padding passes vacuously.
func (in Input) checkSpendable(api frontend.API, env spendEnv, realOrAddress frontend.Variable) frontend.Variable {
	notDummy := api.Sub(1, in.IsDummy)

	assertEqualWhen(api, realOrAddress, in.Utxo.Domain, UtxoDomain)
	constrainProgramZone(api, notDummy, in.Utxo, env.zone, env.zoneAuthority, env.zoneProgramID)

	utxoHash := UtxoHashCircuit(api, in.Utxo)
	// TODO: extract into function check inclusion
	// Inclusion: utxoHash is a leaf of the state tree at UtxoTreeRoot.
	statePathIndices := api.ToBinary(in.StatePathIndex, StateTreeHeight)
	stateRoot := abstractor.Call(api, gadgetlib.MerkleRootGadget{
		Hash:   utxoHash,
		Index:  statePathIndices,
		Path:   in.StatePathElements,
		Height: StateTreeHeight,
	})
	// Dummy and address utxos are not included in the state root.
	assertEqualWhen(api, notDummy, stateRoot, in.UtxoTreeRoot)

	// TODO: extract into function checkOwnerShip
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
	// TODO: extract into function checkNonInclusion
	nullifierPk := abstractor.Call(api, NullifierPkGadget{
		NullifierSecret: in.NullifierSecret,
	})
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
	api.AssertIsEqual(nullifier, in.Nullifier)

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
	api.AssertIsEqual(nfRoot, in.NullifierTreeRoot)
	assertStrictlyOrdered(api, in.NullifierLowValue, in.Nullifier, in.NullifierNextValue)

	return utxoHash
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

// AssertStrictlyOrdered constrains lo < mid < hi, comparing full field values
// (see gadget.IsLessLimbs) — the nullifier tree's indexed-value domain spans
// the whole field. Backs the non-inclusion check in step 3.6. Callers with
// dummy slots must remap them to trivially ordered values before calling.
type AssertStrictlyOrdered struct {
	Lo  frontend.Variable
	Mid frontend.Variable
	Hi  frontend.Variable
}

func (gadget AssertStrictlyOrdered) DefineGadget(api frontend.API) interface{} {
	loLimbs := gadgetlib.CanonicalLimbs(api, gadget.Lo)
	midLimbs := gadgetlib.CanonicalLimbs(api, gadget.Mid)
	hiLimbs := gadgetlib.CanonicalLimbs(api, gadget.Hi)
	api.AssertIsEqual(gadgetlib.IsLessLimbs(api, loLimbs, midLimbs), 1)
	api.AssertIsEqual(gadgetlib.IsLessLimbs(api, midLimbs, hiLimbs), 1)
	return []frontend.Variable{}
}

func assertStrictlyOrdered(api frontend.API, lo, mid, hi frontend.Variable) {
	abstractor.CallVoid(api, AssertStrictlyOrdered{Lo: lo, Mid: mid, Hi: hi})
}
