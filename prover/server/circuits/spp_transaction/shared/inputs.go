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
type PublicInputUtxoInputs struct {
	Nullifier         frontend.Variable
	UtxoTreeRoot      frontend.Variable
	NullifierTreeRoot frontend.Variable
	SignerPk          frontend.Variable
}

func NewInputs(n int) []Input {
	inputs := make([]Input, n)
	for i := range inputs {
		inputs[i].StatePathElements = make([]frontend.Variable, StateTreeHeight)
		inputs[i].NullifierLowPathElements = make([]frontend.Variable, NullifierTreeHeight)
	}
	return inputs
}

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

func inputUtxos(inputs []Input) []UtxoCircuitFields {
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

func constrainInput(api frontend.API, in Input, signals PublicInputUtxoInputs) (frontend.Variable, frontend.Variable) {

	isUtxo := in.isUtxo(api)
	isAddress := in.isAddress(api)
	api.AssertIsEqual(api.Add(isUtxo, isAddress, in.isDummy(api)), 1)

	// Asset 0 marks content-less slots (dummies, addresses). A spendable utxo
	// must name a real asset, which also makes asset-0 public movement slots
	// unbalanceable. Tokenless data utxos use SOL as asset.
	assertZeroWhen(api, isUtxo, api.IsZero(in.Utxo.Asset))

	// The nullifier non-inclusion check runs for every slot kind, dummy and
	// address included.
	utxoHash := UtxoHashCircuit(api, in.Utxo)
	in.checkNonInclusion(api, utxoHash, signals)

	{
		nullifierPk := abstractor.Call(api, nullifierPkGadget{
			NullifierSecret: in.NullifierSecret,
		})
		ownerHash := abstractor.Call(api, OwnerHashGadget{
			OwnerKeyHash: signals.SignerPk,
			NullifierPk:  nullifierPk,
		})
		ownerIsCorrect := api.IsZero(api.Sub(ownerHash, in.Utxo.Owner))
		AssertWhen(api, in.isUtxoOrAddress(api), ownerIsCorrect)
	}

	AssertWhen(api, isUtxo, in.checkInclusion(api, utxoHash, signals.UtxoTreeRoot))

	AssertWhen(api, in.isDummy(api), in.Utxo.CheckDummy(api))
	assertZeroWhen(api, in.isDummy(api), in.NullifierSecret)

	AssertWhen(api, isAddress, in.checkAddress(api))

	// Only UTXOs and addresses must be accessible as such
	// in zk program proofs via private transaction hash.
	inputHash := api.Select(isUtxo, utxoHash, frontend.Variable(0))
	addressHash := api.Select(isAddress, utxoHash, frontend.Variable(0))
	return inputHash, addressHash
}

func (in Input) isUtxo(api frontend.API) frontend.Variable {
	return in.Utxo.isUtxo(api)
}

func (in Input) isAddress(api frontend.API) frontend.Variable {
	return in.Utxo.isAddress(api)
}

func (in Input) isDummy(api frontend.API) frontend.Variable {
	return in.Utxo.isDummy(api)
}

func (in Input) isUtxoOrAddress(api frontend.API) frontend.Variable {
	return in.Utxo.isUtxoOrAddress(api)
}

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
		in.Utxo.RingDataHash,
		in.Utxo.RingProgramID,
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
func (in Input) checkNonInclusion(api frontend.API, utxoHash frontend.Variable, signals PublicInputUtxoInputs) {
	nullifier := abstractor.Call(api, NullifierGadget{
		UtxoHash:        utxoHash,
		Blinding:        in.Utxo.Blinding,
		NullifierSecret: in.NullifierSecret,
	})
	api.AssertIsEqual(nullifier, signals.Nullifier)

	lowLeafHash := gadgetlib.IndexedLeafHash(api, in.NullifierLowValue, in.NullifierNextValue)
	nfPathIndices := api.ToBinary(in.NullifierLowPathIndex, NullifierTreeHeight)
	nfRoot := abstractor.Call(api, gadgetlib.MerkleRootGadget{
		Hash:   lowLeafHash,
		Index:  nfPathIndices,
		Path:   in.NullifierLowPathElements,
		Height: NullifierTreeHeight,
	})
	api.AssertIsEqual(nfRoot, signals.NullifierTreeRoot)
	assertStrictlyOrdered(api, in.NullifierLowValue, signals.Nullifier, in.NullifierNextValue)
}

type nullifierPkGadget struct {
	NullifierSecret frontend.Variable
}

func (gadget nullifierPkGadget) DefineGadget(api frontend.API) interface{} {
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
