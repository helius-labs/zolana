package shared

import (
	gadgetlib "zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

type Input struct {
	Utxo              UtxoCircuitFields
	StatePathElements []frontend.Variable
	StatePathIndex    frontend.Variable

	NullifierLowValue        frontend.Variable
	NullifierNextValue       frontend.Variable
	NullifierLowPathElements []frontend.Variable
	NullifierLowPathIndex    frontend.Variable

	UtxoTreeRoot      frontend.Variable
	NullifierTreeRoot frontend.Variable
	Nullifier         frontend.Variable

	OwnerPkHash     frontend.Variable
	NullifierSecret frontend.Variable
}

// SpendEnv holds the per-proof values shared by every input-spend check: the
// one witnessed P256 key and the one signature over private_tx_hash that
// authorize all P256-owned inputs.
type SpendEnv struct {
	P256PkField  frontend.Variable
	P256SigValid frontend.Variable
	// P256Sentinel marks a P256-owned entry: an OwnerPkHash equal to it routes
	// ownership to the shared P256 key. The default zone uses the public
	// P256SigningPkField, so P256 input owners are public; the custom zone
	// variants route anonymously on the 0 sentinel.
	P256Sentinel frontend.Variable
}

// ConstrainP256Input — P256 rail: a P256-owned entry needs the valid shared
// signature.
func ConstrainP256Input(api frontend.API, in Input, env SpendEnv) (frontend.Variable, frontend.Variable) {
	AssertWhen(api, in.isUtxoOrAddress(api), in.checkOwnershipP256(api, env))
	return constrainInputShared(api, in)
}

// ConstrainEddsaOnlyInput — Solana-only rail: P256-owned entries are rejected.
func ConstrainEddsaOnlyInput(api frontend.API, in Input, env SpendEnv) (frontend.Variable, frontend.Variable) {
	AssertWhen(api, in.isUtxoOrAddress(api), in.checkOwnershipEddsaOnly(api, env))
	return constrainInputShared(api, in)
}

// CheckZoneMember returns 1 iff the utxo is owned by the public zone.
func (c *Circuit) CheckZoneMember(api frontend.API, u UtxoCircuitFields) frontend.Variable {
	return api.IsZero(api.Sub(u.ZoneProgramID, c.ZoneProgramID))
}

// CheckZoneMemberOrFree returns 1 iff the utxo is owned by the signing zone or
// is not a member of any zone; zone data always needs a zone program.
func (c *Circuit) CheckZoneMemberOrFree(api frontend.API, u UtxoCircuitFields) frontend.Variable {
	inCustomZone := api.Sub(1, api.IsZero(u.ZoneProgramID))
	isMemberOfSigningZone := api.IsZero(api.Sub(u.ZoneProgramID, c.ZoneProgramID))
	dataSet := api.Sub(1, api.IsZero(u.ZoneDataHash))
	// If it is in custom zone it must be member of signing zone.
	ok := api.Select(inCustomZone, isMemberOfSigningZone, frontend.Variable(1))
	// Data must only be set if it is in custom zone.
	return api.Mul(ok, api.Select(dataSet, inCustomZone, frontend.Variable(1)))
}

func constrainInputShared(api frontend.API, in Input) (frontend.Variable, frontend.Variable) {
	isUtxo := in.IsUtxo(api)
	isAddress := in.isAddress(api)
	api.AssertIsEqual(api.Add(isUtxo, isAddress, in.isDummy(api)), 1)

	utxoHash := UtxoHashCircuit(api, in.Utxo)
	in.checkNonInclusion(api, utxoHash)

	AssertWhen(api, isUtxo, in.checkInclusion(api, utxoHash))
	AssertWhen(api, in.isDummy(api), in.Utxo.checkDummy(api))
	AssertWhen(api, isAddress, in.checkAddress(api))

	inputHash := api.Select(isUtxo, utxoHash, frontend.Variable(0))
	addressHash := api.Select(isAddress, utxoHash, frontend.Variable(0))
	return inputHash, addressHash
}

// IsUtxo: the slot spends an existing utxo.
func (in Input) IsUtxo(api frontend.API) frontend.Variable {
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

// isUtxoOrAddress: the slot carries content — a spendable or an address utxo.
func (in Input) isUtxoOrAddress(api frontend.API) frontend.Variable {
	return api.Sub(1, in.isDummy(api))
}

// checkInclusion — spendable utxo: returns 1 iff the utxo is a leaf of the
// state tree at UtxoTreeRoot. Ownership is checked via checkOwnership and the
// zone fields via the zone wrappers; asset and amount are constrained by
// balance conservation; blinding and data hash carry no additional checks.
func (in Input) checkInclusion(api frontend.API, utxoHash frontend.Variable) frontend.Variable {
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

// TODO: remove isP256 bool and refactor in eddsa and p256 and
// checkOwnership returns 1 iff the owner binds to the witnessed keys, plus the
// isP256 bit for the caller's rail rule: an OwnerPkHash equal to the P256
// sentinel routes to the shared P256 key (substituted via Select), any other
// entry is the owner key itself.
func (in Input) checkOwnership(api frontend.API, env SpendEnv) (frontend.Variable, frontend.Variable) {
	isP256 := api.IsZero(api.Sub(in.OwnerPkHash, env.P256Sentinel))
	ownerKeyHash := api.Select(isP256, env.P256PkField, in.OwnerPkHash)
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
func (in Input) checkOwnershipP256(api frontend.API, env SpendEnv) frontend.Variable {
	ok, isP256 := in.checkOwnership(api, env)
	// TODO: check whether we shouldnt always abort if p256 sig is invalid.
	return api.Mul(ok, api.Select(isP256, env.P256SigValid, frontend.Variable(1)))
}

// checkOwnershipEddsaOnly — Solana-only rail: P256-owned entries are rejected.
func (in Input) checkOwnershipEddsaOnly(api frontend.API, env SpendEnv) frontend.Variable {
	ok, isP256 := in.checkOwnership(api, env)
	return api.Mul(ok, api.Sub(1, isP256))
}

// 1. derived nullifier equals public nullifier.
// 2. indexed leaf  H(in.NullifierLowValue, in.NullifierNextValue) exists in nullifier tree.
// 3. nullifier is in range (NullifierLowValue < Nullifier < NullifierNextValue)
// -> nullifier does not exist yet in indexed Merkle tree.
func (in Input) checkNonInclusion(api frontend.API, utxoHash frontend.Variable) {
	nullifier := abstractor.Call(api, NullifierGadget{
		UtxoHash:        utxoHash,
		Blinding:        in.Utxo.Blinding,
		NullifierSecret: in.NullifierSecret,
	})
	// 1. Derived nullifier equals public nullifier.
	api.AssertIsEqual(nullifier, in.Nullifier)

	// 2. indexed leaf  H(in.NullifierLowValue, in.NullifierNextValue) exists in nullifier tree.
	lowLeafHash := gadgetlib.IndexedLeafHash(api, in.NullifierLowValue, in.NullifierNextValue)
	nfPathIndices := api.ToBinary(in.NullifierLowPathIndex, NullifierTreeHeight)
	nfRoot := abstractor.Call(api, gadgetlib.MerkleRootGadget{
		Hash:   lowLeafHash,
		Index:  nfPathIndices,
		Path:   in.NullifierLowPathElements,
		Height: NullifierTreeHeight,
	})
	api.AssertIsEqual(nfRoot, in.NullifierTreeRoot)
	// 3.  nullifier is in range (NullifierLowValue < Nullifier < NullifierNextValue)
	assertStrictlyOrdered(api, in.NullifierLowValue, in.Nullifier, in.NullifierNextValue)
}

func (c *Circuit) InputUtxos() []UtxoCircuitFields {
	out := make([]UtxoCircuitFields, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].Utxo
	}
	return out
}

func (c *Circuit) InputNullifiers() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].Nullifier
	}
	return out
}

func (c *Circuit) InputUtxoRoots() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].UtxoTreeRoot
	}
	return out
}

func (c *Circuit) InputNullifierTreeRoots() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].NullifierTreeRoot
	}
	return out
}

func (c *Circuit) InputOwnerPkHashes() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].OwnerPkHash
	}
	return out
}

func (c *Circuit) AssertDistinctNullifiers(api frontend.API) {
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
