package shared

import (
	"fmt"

	gadgetlib "zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// Input is the pure per-slot spend witness. The per-slot protocol-public
// signals (nullifier, tree roots, owner pk hash) live in each variant's Public
// struct (Private for the zone-authority owner tags) and reach the constraint
// helpers as InputSignals.
type Input struct {
	Utxo              UtxoCircuitFields
	StatePathElements []frontend.Variable
	StatePathIndex    frontend.Variable

	NullifierLowValue        frontend.Variable
	NullifierNextValue       frontend.Variable
	NullifierLowPathElements []frontend.Variable
	NullifierLowPathIndex    frontend.Variable

	NullifierSecret frontend.Variable
}

// InputSignals carries one input slot's hoisted signals: the derived
// nullifier, the claimed tree roots, and the owner tag the ownership check
// binds to.
type InputSignals struct {
	Nullifier         frontend.Variable
	UtxoTreeRoot      frontend.Variable
	NullifierTreeRoot frontend.Variable
	OwnerPkHash       frontend.Variable
}

// NewInputs allocates n input slots with tree-height path slices.
func NewInputs(n int) []Input {
	inputs := make([]Input, n)
	for i := range inputs {
		inputs[i].StatePathElements = make([]frontend.Variable, StateTreeHeight)
		inputs[i].NullifierLowPathElements = make([]frontend.Variable, NullifierTreeHeight)
	}
	return inputs
}

// ValidateInputs checks the input count and path heights the circuit relies on
// to size its witness.
func ValidateInputs(nInputs int, inputs []Input) error {
	if len(inputs) != nInputs {
		return fmt.Errorf("spp: input count mismatch: got %d want %d", len(inputs), nInputs)
	}
	for i, input := range inputs {
		if got := len(input.StatePathElements); got != StateTreeHeight {
			return fmt.Errorf("spp: input %d state path height: got %d want %d", i, got, StateTreeHeight)
		}
		if got := len(input.NullifierLowPathElements); got != NullifierTreeHeight {
			return fmt.Errorf("spp: input %d nullifier path height: got %d want %d", i, got, NullifierTreeHeight)
		}
	}
	return nil
}

// InputUtxos projects the utxo fields for balance conservation.
func InputUtxos(inputs []Input) []UtxoCircuitFields {
	out := make([]UtxoCircuitFields, len(inputs))
	for i := range inputs {
		out[i] = inputs[i].Utxo
	}
	return out
}

// AssertDistinctNullifiers asserts pairwise inequality so no input slot is
// spent twice within one proof.
func AssertDistinctNullifiers(api frontend.API, nullifiers []frontend.Variable) {
	for i := range nullifiers {
		for j := i + 1; j < len(nullifiers); j++ {
			api.AssertIsDifferent(nullifiers[i], nullifiers[j])
		}
	}
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
func ConstrainP256Input(api frontend.API, in Input, signals InputSignals, env SpendEnv) (frontend.Variable, frontend.Variable) {
	AssertWhen(api, in.isUtxoOrAddress(api), in.checkOwnershipP256(api, signals.OwnerPkHash, env))
	return constrainInputShared(api, in, signals)
}

// ConstrainEddsaOnlyInput — Solana-only rail: P256-owned entries are rejected.
func ConstrainEddsaOnlyInput(api frontend.API, in Input, signals InputSignals, env SpendEnv) (frontend.Variable, frontend.Variable) {
	AssertWhen(api, in.isUtxoOrAddress(api), in.checkOwnershipEddsaOnly(api, signals.OwnerPkHash, env))
	return constrainInputShared(api, in, signals)
}

// CheckZoneMember returns 1 iff the utxo is owned by the public zone.
func CheckZoneMember(api frontend.API, u UtxoCircuitFields, zoneProgramID frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(u.ZoneProgramID, zoneProgramID))
}

// CheckZoneMemberOrFree returns 1 iff the utxo is owned by the signing zone or
// is not a member of any zone; zone data always needs a zone program.
func CheckZoneMemberOrFree(api frontend.API, u UtxoCircuitFields, zoneProgramID frontend.Variable) frontend.Variable {
	inCustomZone := api.Sub(1, api.IsZero(u.ZoneProgramID))
	isMemberOfSigningZone := api.IsZero(api.Sub(u.ZoneProgramID, zoneProgramID))
	dataSet := api.Sub(1, api.IsZero(u.ZoneDataHash))
	// If it is in custom zone it must be member of signing zone.
	ok := api.Select(inCustomZone, isMemberOfSigningZone, frontend.Variable(1))
	// Data must only be set if it is in custom zone.
	return api.Mul(ok, api.Select(dataSet, inCustomZone, frontend.Variable(1)))
}

func constrainInputShared(api frontend.API, in Input, signals InputSignals) (frontend.Variable, frontend.Variable) {
	isUtxo := in.IsUtxo(api)
	isAddress := in.isAddress(api)
	api.AssertIsEqual(api.Add(isUtxo, isAddress, in.isDummy(api)), 1)

	utxoHash := UtxoHashCircuit(api, in.Utxo)
	in.checkNonInclusion(api, utxoHash, signals)

	AssertWhen(api, isUtxo, in.checkInclusion(api, utxoHash, signals.UtxoTreeRoot))
	AssertWhen(api, in.isDummy(api), in.Utxo.checkDummy(api))
	AssertWhen(api, isAddress, in.checkAddress(api))

	inputHash := api.Select(isUtxo, utxoHash, frontend.Variable(0))
	addressHash := api.Select(isAddress, utxoHash, frontend.Variable(0))
	return inputHash, addressHash
}

// IsUtxo: the slot spends an existing utxo.
func (in Input) IsUtxo(api frontend.API) frontend.Variable {
	return in.Utxo.IsUtxo(api)
}

// isAddress: the slot creates an address, owner signed.
func (in Input) isAddress(api frontend.API) frontend.Variable {
	return in.Utxo.isAddress(api)
}

// isDummy: the slot is padding and carries nothing.
func (in Input) isDummy(api frontend.API) frontend.Variable {
	return in.Utxo.isDummy(api)
}

// isUtxoOrAddress: the slot carries content — a spendable or an address utxo.
func (in Input) isUtxoOrAddress(api frontend.API) frontend.Variable {
	return in.Utxo.isUtxoOrAddress(api)
}

// checkInclusion — spendable utxo: returns 1 iff the utxo is a leaf of the
// state tree at utxoTreeRoot. Ownership is checked via checkOwnership and the
// zone fields via the zone wrappers; asset and amount are constrained by
// balance conservation; blinding and data hash carry no additional checks.
func (in Input) checkInclusion(api frontend.API, utxoHash, utxoTreeRoot frontend.Variable) frontend.Variable {
	statePathIndices := api.ToBinary(in.StatePathIndex, StateTreeHeight)
	stateRoot := abstractor.Call(api, gadgetlib.MerkleRootGadget{
		Hash:   utxoHash,
		Index:  statePathIndices,
		Path:   in.StatePathElements,
		Height: StateTreeHeight,
	})
	return api.IsZero(api.Sub(stateRoot, utxoTreeRoot))
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
// isP256 bit for the caller's rail rule: an ownerPkHash equal to the P256
// sentinel routes to the shared P256 key (substituted via Select), any other
// entry is the owner key itself.
func (in Input) checkOwnership(api frontend.API, ownerPkHash frontend.Variable, env SpendEnv) (frontend.Variable, frontend.Variable) {
	isP256 := api.IsZero(api.Sub(ownerPkHash, env.P256Sentinel))
	ownerKeyHash := api.Select(isP256, env.P256PkField, ownerPkHash)
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
func (in Input) checkOwnershipP256(api frontend.API, ownerPkHash frontend.Variable, env SpendEnv) frontend.Variable {
	ok, isP256 := in.checkOwnership(api, ownerPkHash, env)
	// TODO: check whether we shouldnt always abort if p256 sig is invalid.
	return api.Mul(ok, api.Select(isP256, env.P256SigValid, frontend.Variable(1)))
}

// checkOwnershipEddsaOnly — Solana-only rail: P256-owned entries are rejected.
func (in Input) checkOwnershipEddsaOnly(api frontend.API, ownerPkHash frontend.Variable, env SpendEnv) frontend.Variable {
	ok, isP256 := in.checkOwnership(api, ownerPkHash, env)
	return api.Mul(ok, api.Sub(1, isP256))
}

//  1. derived nullifier equals the public nullifier.
//  2. indexed leaf H(in.NullifierLowValue, in.NullifierNextValue) exists in the
//     nullifier tree at signals.NullifierTreeRoot.
//  3. nullifier is in range (NullifierLowValue < Nullifier < NullifierNextValue)
//
// -> nullifier does not exist yet in indexed Merkle tree.
func (in Input) checkNonInclusion(api frontend.API, utxoHash frontend.Variable, signals InputSignals) {
	nullifier := abstractor.Call(api, NullifierGadget{
		UtxoHash:        utxoHash,
		Blinding:        in.Utxo.Blinding,
		NullifierSecret: in.NullifierSecret,
	})
	// 1. Derived nullifier equals public nullifier.
	api.AssertIsEqual(nullifier, signals.Nullifier)

	// 2. indexed leaf H(in.NullifierLowValue, in.NullifierNextValue) exists in nullifier tree.
	lowLeafHash := gadgetlib.IndexedLeafHash(api, in.NullifierLowValue, in.NullifierNextValue)
	nfPathIndices := api.ToBinary(in.NullifierLowPathIndex, NullifierTreeHeight)
	nfRoot := abstractor.Call(api, gadgetlib.MerkleRootGadget{
		Hash:   lowLeafHash,
		Index:  nfPathIndices,
		Path:   in.NullifierLowPathElements,
		Height: NullifierTreeHeight,
	})
	api.AssertIsEqual(nfRoot, signals.NullifierTreeRoot)
	// 3.  nullifier is in range (NullifierLowValue < Nullifier < NullifierNextValue)
	assertStrictlyOrdered(api, in.NullifierLowValue, signals.Nullifier, in.NullifierNextValue)
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
