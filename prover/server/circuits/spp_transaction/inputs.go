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
	// p256Sentinel marks a P256-owned entry: an OwnerPkHash equal to it routes
	// ownership to the shared P256 key. The default zone uses the public
	// p256SigningPkField, so P256 input owners are public; the custom zone
	// variants route anonymously on the 0 sentinel.
	p256Sentinel frontend.Variable
}

func (c *Circuit) assertInputs(api frontend.API, env spendEnv) ([]frontend.Variable, []frontend.Variable) {
	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	addressHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i := 0; i < c.Shape.NInputs; i++ {
		if c.Confidential {
			inputHashes[i], addressHashes[i] = c.constrainDefaultZoneInput(api, c.Inputs[i], env)
		} else {
			inputHashes[i], addressHashes[i] = c.constrainZoneInput(api, c.Inputs[i], env)
		}
	}
	c.assertDistinctNullifiers(api)
	return inputHashes, addressHashes
}

// constrainDefaultZoneInput — default zone: a real input must not be a member
// of a zone, and P256 owners are public (the sentinel is the shared signing
// key).
func (c *Circuit) constrainDefaultZoneInput(api frontend.API, in Input, env spendEnv) (frontend.Variable, frontend.Variable) {
	assertWhen(api, in.isReal(api), in.Utxo.checkNotInZone(api))
	env.p256Sentinel = c.P256SigningPkField
	if c.RequiresP256 {
		return constrainP256Input(api, in, env)
	}
	return constrainEddsaOnlyInput(api, in, env)
}

// constrainZoneInput — custom zone: a real input is either owned by the public
// zone or not a member of any zone; the zone-authority variant requires zone
// ownership for every real input. P256 owners route anonymously on the 0
// sentinel.
func (c *Circuit) constrainZoneInput(api frontend.API, in Input, env spendEnv) (frontend.Variable, frontend.Variable) {
	if c.ZoneAuthority {
		assertWhen(api, in.isReal(api), c.checkZoneMember(api, in.Utxo))
	} else {
		assertWhen(api, in.isReal(api), c.checkZoneMemberOrFree(api, in.Utxo))
	}
	env.p256Sentinel = frontend.Variable(0)
	if c.RequiresP256 {
		return constrainP256Input(api, in, env)
	}
	return constrainEddsaOnlyInput(api, in, env)
}

// constrainP256Input — P256 rail: a P256-owned entry needs the valid shared
// signature.
func constrainP256Input(api frontend.API, in Input, env spendEnv) (frontend.Variable, frontend.Variable) {
	assertWhen(api, in.isRealOrAddress(api), in.checkOwnershipP256(api, env))
	return constrainInputShared(api, in)
}

// constrainEddsaOnlyInput — Solana-only rail: P256-owned entries are rejected.
func constrainEddsaOnlyInput(api frontend.API, in Input, env spendEnv) (frontend.Variable, frontend.Variable) {
	assertWhen(api, in.isRealOrAddress(api), in.checkOwnershipEddsaOnly(api, env))
	return constrainInputShared(api, in)
}

// checkZoneMember returns 1 iff the utxo is owned by the public zone.
func (c *Circuit) checkZoneMember(api frontend.API, u UtxoCircuitFields) frontend.Variable {
	return api.IsZero(api.Sub(u.ZoneProgramID, c.ZoneProgramID))
}

// checkZoneMemberOrFree returns 1 iff the utxo is owned by the public zone or
// is not a member of any zone; zone data always needs a zone program.
func (c *Circuit) checkZoneMemberOrFree(api frontend.API, u UtxoCircuitFields) frontend.Variable {
	inZone := api.Sub(1, api.IsZero(u.ZoneProgramID))
	member := api.IsZero(api.Sub(u.ZoneProgramID, c.ZoneProgramID))
	dataSet := api.Sub(1, api.IsZero(u.ZoneDataHash))
	ok := api.Select(inZone, member, frontend.Variable(1))
	return api.Mul(ok, api.Select(dataSet, inZone, frontend.Variable(1)))
}

func constrainInputShared(api frontend.API, in Input) (frontend.Variable, frontend.Variable) {
	isReal := in.isReal(api)
	isAddress := in.isAddress(api)
	api.AssertIsEqual(api.Add(isReal, isAddress, in.isDummy(api)), 1)

	utxoHash := UtxoHashCircuit(api, in.Utxo)
	in.checkNonInclusion(api, utxoHash)

	assertWhen(api, isReal, in.checkSpendable(api, utxoHash))
	assertWhen(api, in.isDummy(api), in.Utxo.checkDummy(api))
	assertWhen(api, isAddress, in.checkAddress(api))

	inputHash := api.Select(isReal, utxoHash, frontend.Variable(0))
	addressHash := api.Select(isAddress, utxoHash, frontend.Variable(0))
	return inputHash, addressHash
}

// isReal: the slot spends an existing utxo.
func (in Input) isReal(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(in.Utxo.Domain, UtxoDomain))
}

// isAddress: the slot creates an address, owner signed.
func (in Input) isAddress(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(in.Utxo.Domain, AddressDomain))
}

// isDummy: the slot is padding and carries nothing.
func (in Input) isDummy(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(in.Utxo.Domain, DummyDomain))
}

// isRealOrAddress: the slot carries content — a spendable or an address utxo.
func (in Input) isRealOrAddress(api frontend.API) frontend.Variable {
	return api.Sub(1, in.isDummy(api))
}

// checkSpendable — spendable utxo: returns 1 iff the utxo is a leaf of the
// state tree at UtxoTreeRoot. Ownership is checked via checkOwnership and the
// zone fields via the zone wrappers; asset and amount are constrained by
// balance conservation; blinding and data hash carry no additional checks.
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

func (in Input) checkAddress(api frontend.API) frontend.Variable {
	// Owner is signer.
	// Blinding is seed.
	// NullifierSecret is 0, so the address nullifier is derivable from
	// (owner, seed) alone.
	// -> domain separated nullifier by owner which can be used as address
	return allZero(api,
		in.Utxo.Asset,
		in.Utxo.Amount,
		in.Utxo.DataHash,
		in.Utxo.ZoneDataHash,
		in.Utxo.ZoneProgramID,
		in.NullifierSecret,
	)
}

func allZero(api frontend.API, values ...frontend.Variable) frontend.Variable {
	zero := frontend.Variable(1)
	for _, v := range values {
		zero = api.Mul(zero, api.IsZero(v))
	}
	return zero
}

// checkOwnership returns 1 iff the owner binds to the witnessed keys, plus the
// isP256 bit for the caller's rail rule: an OwnerPkHash equal to the P256
// sentinel routes to the shared P256 key (substituted via Select), any other
// entry is the owner key itself.
func (in Input) checkOwnership(api frontend.API, env spendEnv) (frontend.Variable, frontend.Variable) {
	isP256 := api.IsZero(api.Sub(in.OwnerPkHash, env.p256Sentinel))
	ownerKeyHash := api.Select(isP256, env.p256PkField, in.OwnerPkHash)
	nullifierPk := abstractor.Call(api, NullifierPkGadget{
		NullifierSecret: in.NullifierSecret,
	})
	ownerHash := abstractor.Call(api, OwnerHashGadget{
		OwnerKeyHash: ownerKeyHash,
		NullifierPk:  nullifierPk,
	})
	ok := api.IsZero(api.Sub(ownerHash, in.Utxo.Owner))
	return ok, isP256
}

// checkOwnershipP256 — P256 rail: a P256-owned entry additionally needs the
// valid shared signature.
func (in Input) checkOwnershipP256(api frontend.API, env spendEnv) frontend.Variable {
	ok, isP256 := in.checkOwnership(api, env)
	return api.Mul(ok, api.Select(isP256, env.p256SigValid, frontend.Variable(1)))
}

// checkOwnershipEddsaOnly — Solana-only rail: P256-owned entries are rejected.
func (in Input) checkOwnershipEddsaOnly(api frontend.API, env spendEnv) frontend.Variable {
	ok, isP256 := in.checkOwnership(api, env)
	return api.Mul(ok, api.Sub(1, isP256))
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
