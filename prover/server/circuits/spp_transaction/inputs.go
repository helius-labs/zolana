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
// An input slot is one of three kinds: a spendable utxo (IsDummy == 0), an
// address utxo (IsDummy == 1 with a data hash), or a dummy utxo (IsDummy == 1
// without). Every kind carries the utxo domain and proves nullifier
// non-inclusion; checkSpendable, checkDummy, and checkAddress hold the
// remaining per-kind checks, with spendable and address utxos binding their
// owner via checkOwnership. All other utxo fields are bound by the utxo hash;
// the blinding stays unconstrained for every kind so dummy and address
// nullifiers are indistinguishable from spendable ones.
func constrainInput(api frontend.API, in Input, env spendEnv) (frontend.Variable, frontend.Variable) {
	api.AssertIsBoolean(in.IsDummy)

	api.AssertIsEqual(in.Utxo.Domain, UtxoDomain)
	utxoHash := UtxoHashCircuit(api, in.Utxo)
	in.checkNonInclusion(api, utxoHash)

	assertWhen(api, in.isReal(api), in.checkSpendable(api, utxoHash))
	assertWhen(api, in.isDummy(api), in.checkDummy(api))
	assertWhen(api, in.isAddress(api), in.checkAddress(api))
	assertWhen(api, in.isRealOrAddress(api), in.checkOwnership(api, env))

	inputHash := api.Select(in.IsDummy, frontend.Variable(0), utxoHash)
	addressHash := api.Select(in.isAddress(api), utxoHash, frontend.Variable(0))
	return inputHash, addressHash
}

// isReal: the slot spends an existing utxo.
func (in Input) isReal(api frontend.API) frontend.Variable {
	return api.Sub(1, in.IsDummy)
}

// isAddress: a dummy slot whose data hash is set creates an address, owner signed.
func (in Input) isAddress(api frontend.API) frontend.Variable {
	dataIsSet := api.Sub(1, api.IsZero(in.Utxo.DataHash))
	return api.Mul(in.IsDummy, dataIsSet)
}

// isDummy: a dummy slot all fields other than domain and blinding are zero values.
func (in Input) isDummy(api frontend.API) frontend.Variable {
	return api.Sub(in.IsDummy, in.isAddress(api))
}

// isRealOrAddress: the slot carries content — a spendable or an address utxo.
func (in Input) isRealOrAddress(api frontend.API) frontend.Variable {
	return api.Sub(1, in.isDummy(api))
}

// checkSpendable — spendable utxo: returns 1 iff the utxo is a leaf of the
// state tree at UtxoTreeRoot. Ownership is checked via checkOwnership; asset
// and amount are constrained by balance conservation; blinding, data hash, and
// the zone fields carry no additional checks (the zone fields were bound when
// the utxo was created as an output).
func (in Input) checkSpendable(api frontend.API, utxoHash frontend.Variable) frontend.Variable {
	statePathIndices := api.ToBinary(in.StatePathIndex, StateTreeHeight)
	stateRoot := abstractor.Call(api, gadgetlib.MerkleRootGadget{
		Hash:   utxoHash,
		Index:  statePathIndices,
		Path:   in.StatePathElements,
		Height: StateTreeHeight,
	})
	return api.IsZero(api.Sub(stateRoot, in.UtxoTreeRoot))
}

// checkDummy — dummy utxo: returns 1 iff every field except the blinding is
// zero, so the slot carries nothing. The zero data hash is the kind classifier
// itself.
func (in Input) checkDummy(api frontend.API) frontend.Variable {
	return allZero(api,
		in.Utxo.Owner,
		in.Utxo.Asset,
		in.Utxo.Amount,
		in.Utxo.ZoneDataHash,
		in.Utxo.ZoneProgramID,
	)
}

// checkAddress — address utxo: returns 1 iff only the owner and data hash
// carry content — the value and zone fields are zero. Ownership is checked via
// checkOwnership.
func (in Input) checkAddress(api frontend.API) frontend.Variable {
	return allZero(api,
		in.Utxo.Asset,
		in.Utxo.Amount,
		in.Utxo.ZoneDataHash,
		in.Utxo.ZoneProgramID,
	)
}

func allZero(api frontend.API, values ...frontend.Variable) frontend.Variable {
	zero := frontend.Variable(1)
	for _, v := range values {
		zero = api.Mul(zero, api.IsZero(v))
	}
	return zero
}

// checkOwnership returns 1 iff the owner binds to the witnessed keys: select
// the input's path and recompute the owner. Anonymous routes on the 0 sentinel
// — 0 binds to the shared P256 key (substituted via Select), non-zero to the
// entry. Confidential routes by equality to the public p256SigningPkField, so
// a P256 owner's pk_field is public in OwnerPkHash and is already the owner
// key — no substitution, so the Select is omitted. A P256 owner additionally
// needs the valid shared signature; the Solana-only rail rejects P256 owners
// outright.
func (in Input) checkOwnership(api frontend.API, env spendEnv) frontend.Variable {
	var isP256, ownerKeyHash frontend.Variable
	if env.isCustomZone {
		isP256 = api.IsZero(api.Sub(in.OwnerPkHash, env.p256SigningPkField))
		ownerKeyHash = in.OwnerPkHash
	} else {
		isP256 = api.IsZero(in.OwnerPkHash)
		ownerKeyHash = api.Select(isP256, env.p256PkField, in.OwnerPkHash)
	}
	nullifierPk := abstractor.Call(api, NullifierPkGadget{
		NullifierSecret: in.NullifierSecret,
	})
	ownerHash := abstractor.Call(api, OwnerHashGadget{
		OwnerKeyHash: ownerKeyHash,
		NullifierPk:  nullifierPk,
	})
	ok := api.IsZero(api.Sub(ownerHash, in.Utxo.Owner))
	if env.requiresP256 {
		ok = api.Mul(ok, api.Select(isP256, env.p256SigValid, frontend.Variable(1)))
	} else {
		ok = api.Mul(ok, api.Sub(1, isP256))
	}
	return ok
}

// checkNonInclusion: the nullifier is bound to the utxo and absent from the
// nullifier tree — the low leaf is in the tree and brackets the nullifier
// (NullifierLowValue < Nullifier < NullifierNextValue).
func (in Input) checkNonInclusion(api frontend.API, utxoHash frontend.Variable) {
	nullifier := abstractor.Call(api, NullifierGadget{
		UtxoHash:        utxoHash,
		Blinding:        in.Utxo.Blinding,
		NullifierSecret: in.NullifierSecret,
	})
	api.AssertIsEqual(nullifier, in.Nullifier)

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
