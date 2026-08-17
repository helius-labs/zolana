package shared

import (
	"fmt"

	gadgetlib "zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// SpendSecretBits bounds the spend secret scalar. The subgroup order is 251 bits
// while the scalar field is 254, so without this bound secret, secret+order, ...
// secret+7*order would be distinct field elements sharing one public key, each
// deriving a different nullifier for the same UTXO. Mirrors
// protocol.SpendSecretBits.
const SpendSecretBits = 250

// Input UTXO with inclusion and non inclusion proofs.
type Input struct {
	Utxo              UtxoCircuitFields
	StatePathElements []frontend.Variable
	StatePathIndex    frontend.Variable

	NullifierLowValue        frontend.Variable
	NullifierNextValue       frontend.Variable
	NullifierLowPathElements []frontend.Variable
	NullifierLowPathIndex    frontend.Variable

	// NullifierSecret is the spend secret scalar: it derives the nullifier and
	// is bound to SpendPublic by a base-point multiplication.
	NullifierSecret frontend.Variable

	// SpendPublic is committed by the UTXO's owner hash, and SpendSignature
	// authorizes this spend under it. Slots that do not spend (dummy padding and
	// address slots) carry the neutral element and its trivially valid
	// signature, so every curve check below runs ungated.
	SpendPublic    eddsa.PublicKey
	SpendSignature eddsa.Signature
}

// Public inputs per input UTXO.
type PublicInputUtxoInputs struct {
	Nullifier         frontend.Variable
	UtxoTreeRoot      frontend.Variable
	NullifierTreeRoot frontend.Variable
	SignerPk          frontend.Variable
	// SpendMessage is the transaction's private hash, which every input
	// signature covers, so a signature cannot be replayed into another
	// transaction.
	SpendMessage frontend.Variable
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

func constrainInput(
	api frontend.API,
	curve twistededwards.Curve,
	in Input,
	signals PublicInputUtxoInputs,
) (frontend.Variable, frontend.Variable, error) {

	isUtxo := in.isUtxo(api)
	isAddress := in.isAddress(api)
	api.AssertIsEqual(api.Add(isUtxo, isAddress, in.isDummy(api)), 1)

	// Asset 0 marks content-less slots (dummies, addresses); a spendable utxo
	// must name a real asset. This also makes asset-0 public movement slots
	// unbalanceable, since no spendable utxo can carry asset 0.
	// Tokenless data utxos use SOL as asset.
	assertZeroWhen(api, isUtxo, api.IsZero(in.Utxo.Asset))

	// Checks for UTXO, dummy UTXO, adddress:
	// 1. nullifier must not exist in nullifier tree.
	utxoHash := UtxoHashCircuit(api, in.Utxo)
	in.checkNonInclusion(api, utxoHash, signals)

	// Checks UTXO and address:
	// 1. Check owner hash matches UTXO.
	{
		ownerHash := abstractor.Call(api, ownerHashGadget{
			OwnerKeyHash: signals.SignerPk,
			SpendPkX:     in.SpendPublic.A.X,
			SpendPkY:     in.SpendPublic.A.Y,
		})
		ownerIsCorrect := api.IsZero(api.Sub(ownerHash, in.Utxo.Owner))
		AssertWhen(api, in.isUtxoOrAddress(api), ownerIsCorrect)
	}

	// Spend authority. Every check here runs ungated: non-spending slots carry
	// the neutral element and the signature that verifies under it, which is
	// exactly why a real UTXO must not commit to the neutral element.
	if err := in.constrainSpendAuthority(api, curve, isUtxo, signals.SpendMessage); err != nil {
		return nil, nil, err
	}

	// UTXO checks:
	// 1. UTXO hash must exist in state Merkle tree.
	{
		AssertWhen(api, isUtxo, in.checkInclusion(api, utxoHash, signals.UtxoTreeRoot))
	}
	// Dummy checks:
	// 1. All UTXO fields and nullifier secret 0, except the blinding.
	// 2. Spend key pinned to the neutral element, so a dummy slot cannot smuggle
	//    in a key of its own.
	{
		AssertWhen(api, in.isDummy(api), in.Utxo.CheckDummy(api))
		assertZeroWhen(api, in.isDummy(api), in.NullifierSecret)
		AssertWhen(api, in.isDummy(api), in.spendKeyIsNeutral(api))
	}
	// Address checks:
	// 1. All UTXO fields and nullifier secret 0, except the blinding and owner.
	AssertWhen(api, isAddress, in.checkAddress(api))

	// Only UTXOs and addresses must be accessible as such
	// in zk program proofs via private transaction hash.
	inputHash := api.Select(isUtxo, utxoHash, frontend.Variable(0))
	addressHash := api.Select(isAddress, utxoHash, frontend.Variable(0))
	return inputHash, addressHash, nil
}

// constrainSpendAuthority proves the spender holds the secret of the public key
// the UTXO's owner hash commits to:
//
//  1. the public key and the signature nonce are curve points (gnark's verifier
//     checks neither),
//  2. the signature verifies over the transaction's private hash,
//  3. the nullifier secret is that public key's discrete log, canonically
//     represented — without this a spender could pick any secret and derive an
//     unlimited number of nullifiers for one UTXO,
//  4. a real UTXO does not commit to the neutral element, whose signature anyone
//     can forge.
func (in Input) constrainSpendAuthority(
	api frontend.API,
	curve twistededwards.Curve,
	isUtxo frontend.Variable,
	message frontend.Variable,
) error {
	curve.AssertIsOnCurve(in.SpendPublic.A)
	curve.AssertIsOnCurve(in.SpendSignature.R)

	if err := eddsa.Verify(
		curve,
		in.SpendSignature,
		message,
		in.SpendPublic,
		gadgetlib.NewPoseidonFieldHasher(api),
	); err != nil {
		return fmt.Errorf("spp: spend signature: %w", err)
	}

	api.ToBinary(in.NullifierSecret, SpendSecretBits)
	base := twistededwards.Point{X: curve.Params().Base[0], Y: curve.Params().Base[1]}
	derived := curve.ScalarMul(base, in.NullifierSecret)
	api.AssertIsEqual(derived.X, in.SpendPublic.A.X)
	api.AssertIsEqual(derived.Y, in.SpendPublic.A.Y)

	AssertWhen(api, isUtxo, api.Sub(1, in.spendKeyIsNeutral(api)))
	return nil
}

// spendKeyIsNeutral returns 1 iff the spend public key is the curve's neutral
// element (0, 1), the convention for slots that do not spend.
func (in Input) spendKeyIsNeutral(api frontend.API) frontend.Variable {
	return api.Mul(
		api.IsZero(in.SpendPublic.A.X),
		api.IsZero(api.Sub(in.SpendPublic.A.Y, 1)),
	)
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
	// NullifierSecret is 0 and the spend key is the neutral element, so the
	// address nullifier and its owner hash are derivable from (owner, seed)
	// alone. An unpinned spend key would let one (owner, seed) pair yield
	// unboundedly many addresses and stop them being recomputable off-circuit.
	// -> domain separated nullifier by owner which can be used as address
	return api.Mul(
		allZero(api,
			in.Utxo.Asset,
			in.Utxo.Amount,
			in.Utxo.DataHash,
			in.Utxo.ZoneDataHash,
			in.Utxo.ZoneProgramID,
			in.NullifierSecret,
		),
		in.spendKeyIsNeutral(api),
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
