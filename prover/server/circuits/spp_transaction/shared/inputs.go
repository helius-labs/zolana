package shared

import (
	"fmt"

	gadgetlib "zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// Input UTXO with inclusion and non inclusion proofs.
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

// Public inputs per input UTXO.
type inputSignals struct {
	Nullifier         frontend.Variable
	UtxoTreeRoot      frontend.Variable
	NullifierTreeRoot frontend.Variable
	SignerPk          frontend.Variable
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

// validateInputs checks the input count and path heights the circuit relies on
// to size its witness.
func validateInputs(nInputs int, inputs []Input) error {
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

// inputUtxos projects the utxo fields for balance conservation.
func inputUtxos(inputs []Input) []UtxoCircuitFields {
	out := make([]UtxoCircuitFields, len(inputs))
	for i := range inputs {
		out[i] = inputs[i].Utxo
	}
	return out
}

// assertDistinctNullifiers asserts pairwise inequality so no input slot is
// spent twice within one proof.
func assertDistinctNullifiers(api frontend.API, nullifiers []frontend.Variable) {
	for i := range nullifiers {
		for j := i + 1; j < len(nullifiers); j++ {
			api.AssertIsDifferent(nullifiers[i], nullifiers[j])
		}
	}
}

// constrainInput binds one input slot to its signer. The variant's Signers array
// already resolved which pk hash signs for this slot, so a slot that carries
// content only needs its owner hash to recompute from that pk and the witnessed
// nullifier secret.
func constrainInput(api frontend.API, in Input, signals inputSignals) (frontend.Variable, frontend.Variable) {
	nullifierPk := abstractor.Call(api, nullifierPkGadget{
		NullifierSecret: in.NullifierSecret,
	})
	ownerHash := abstractor.Call(api, ownerHashGadget{
		OwnerKeyHash: signals.SignerPk,
		NullifierPk:  nullifierPk,
	})
	ownerBinds := api.IsZero(api.Sub(ownerHash, in.Utxo.Owner))
	AssertWhen(api, in.isUtxoOrAddress(api), ownerBinds)

	isUtxo := in.isUtxo(api)
	isAddress := in.isAddress(api)
	api.AssertIsEqual(api.Add(isUtxo, isAddress, in.isDummy(api)), 1)

	// Asset 0 marks content-less slots (dummies, addresses); a spendable utxo
	// must name a real asset. This also makes asset-0 public movement slots
	// unbalanceable, since no spendable utxo can carry asset 0.
	assertZeroWhen(api, isUtxo, api.IsZero(in.Utxo.Asset))

	utxoHash := UtxoHashCircuit(api, in.Utxo)
	in.checkNonInclusion(api, utxoHash, signals)

	AssertWhen(api, isUtxo, in.checkInclusion(api, utxoHash, signals.UtxoTreeRoot))
	AssertWhen(api, in.isDummy(api), in.Utxo.checkDummy(api))
	assertZeroWhen(api, in.isDummy(api), in.NullifierSecret)
	AssertWhen(api, isAddress, in.checkAddress(api))

	inputHash := api.Select(isUtxo, utxoHash, frontend.Variable(0))
	addressHash := api.Select(isAddress, utxoHash, frontend.Variable(0))
	return inputHash, addressHash
}

// isUtxo: the slot spends an existing utxo.
func (in Input) isUtxo(api frontend.API) frontend.Variable {
	return in.Utxo.isUtxo(api)
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
// state tree at utxoTreeRoot. Ownership is checked in constrainInput and the
// zone fields by the variant's zone rule; asset and amount are constrained by
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

//  1. derived nullifier equals the public nullifier.
//  2. indexed leaf H(in.NullifierLowValue, in.NullifierNextValue) exists in the
//     nullifier tree at signals.NullifierTreeRoot.
//  3. nullifier is in range (NullifierLowValue < Nullifier < NullifierNextValue)
//
// -> nullifier does not exist yet in indexed Merkle tree.
func (in Input) checkNonInclusion(api frontend.API, utxoHash frontend.Variable, signals inputSignals) {
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

// nullifierPkGadget derives the public nullifier key from the secret (step 3.1).
type nullifierPkGadget struct {
	NullifierSecret frontend.Variable
}

func (gadget nullifierPkGadget) DefineGadget(api frontend.API) interface{} {
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
