// Package merge implements the SPP Merge Proof (spec: Merge Proof - Merge ZK
// Proof). It consolidates up to 8 input UTXOs of a single owner and single asset
// into one output UTXO of the same owner, asset, and total amount, and
// verifiably encrypts the merged output to the owner's viewing key. The proof
// takes no wallet secret beyond the values a sync delegate holds; it checks no
// owner signature, so ownership binds only through the shared nullifier secret
// and state inclusion of the owner hash (the owner pk_field is supplied
// directly, with a unified P256/Ed25519 encoding).
package merge

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/circuits/verifiable-encryption/aes"
	"zolana/prover/circuits/verifiable-encryption/p256"
)

// MergeShape is the single supported merge shape: 8 inputs, 1 output. Fewer than
// 8 real inputs use dummy slots.
const (
	MergeInputs = 8
	UtxoDomain  = transaction.UtxoDomain
	DummyDomain = transaction.DummyDomain
)

type Input struct {
	// Free per-slot UTXO fields. The remaining leaf fields are shared and fed in
	// by the circuit, so they are not witnessed: Owner = user_owner_hash, Asset =
	// the single merged asset, DataHash = 0, ZoneProgramID = the zone program (0 on
	// the default rail). Domain is the slot-type control (UtxoDomain real /
	// DummyDomain padding); ZoneDataHash is free on the zone rail and pinned to 0 on
	// the default rail. A real input whose committed leaf disagrees with the shared
	// values simply fails state inclusion, so uniformity needs no explicit assert.
	Domain       frontend.Variable
	Amount       frontend.Variable
	Blinding     frontend.Variable
	ZoneDataHash frontend.Variable

	StatePathElements []frontend.Variable
	StatePathIndex    frontend.Variable

	NullifierLowValue        frontend.Variable
	NullifierNextValue       frontend.Variable
	NullifierLowPathElements []frontend.Variable
	NullifierLowPathIndex    frontend.Variable
}

type Output struct {
	// The merged output's only free leaf fields. Amount is assembled from the input
	// sum; Owner/Asset/Domain/DataHash/ZoneProgramID are shared/constant.
	// ZoneDataHash is free on the zone rail and 0 on the default rail.
	Blinding     frontend.Variable
	ZoneDataHash frontend.Variable
}

type Circuit struct {
	NumInputs int `gnark:"-"`

	Inputs []Input
	Output Output

	// Asset is the single asset shared by every real input and the merged output.
	Asset frontend.Variable

	// Shared owner identity. OwnerPkHash is the owner's pk_field, supplied directly
	// for both P256 and Ed25519 owners (unified encoding) and bound to the
	// committed leaf by state inclusion. Merge recomputes no owner point, so it
	// witnesses no P256 signing key.
	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable

	// Verifiable encryption witnesses. TxViewingSk is the ephemeral P-256 scalar
	// (a BN254-range field element); UserViewingPubkey is the owner's viewing
	// pubkey as a 65-byte uncompressed point (0x04 || x || y).
	TxViewingSk       frontend.Variable
	UserViewingPubkey [65]frontend.Variable

	publicInputHashInputs

	PublicInputHash frontend.Variable `gnark:",public"`
}

// newInputs builds the MergeInputs input slots with their Merkle-path slices
// sized so gnark allocates the right number of path signals per slot.
func newInputs() []Input {
	inputs := make([]Input, MergeInputs)
	for i := range inputs {
		inputs[i].StatePathElements = make([]frontend.Variable, transaction.StateTreeHeight)
		inputs[i].NullifierLowPathElements = make([]frontend.Variable, transaction.NullifierTreeHeight)
	}
	return inputs
}

func NewMergeCircuit() *Circuit {
	c := &Circuit{
		NumInputs: MergeInputs,
		Inputs:    newInputs(),
	}
	c.allocInputSignals()
	c.Zone = false
	c.ZoneProgramID = frontend.Variable(0)
	return c
}

func (c *Circuit) Define(api frontend.API) error {
	if err := validateLayout(c.NumInputs, c.Inputs); err != nil {
		return err
	}
	publicInputHash, err := defineMerge(api, mergeWitness{
		inputs:              c.Inputs,
		output:              c.Output,
		asset:               c.Asset,
		ownerPkHash:         c.OwnerPkHash,
		userNullifierPk:     c.UserNullifierPk,
		userNullifierSecret: c.UserNullifierSecret,
		txViewingSk:         c.TxViewingSk,
		userViewingPubkey:   c.UserViewingPubkey,
	}, c.publicInputHashInputs)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.PublicInputHash, publicInputHash)
	return nil
}

// mergeWitness carries the private witness defineMerge derives the public-input
// hash from. The prover-supplied inputs to that hash live on the
// publicInputHashInputs the caller passes in, so no signal is declared twice.
type mergeWitness struct {
	inputs              []Input
	output              Output
	asset               frontend.Variable
	ownerPkHash         frontend.Variable
	userNullifierPk     frontend.Variable
	userNullifierSecret frontend.Variable
	txViewingSk         frontend.Variable
	userViewingPubkey   [65]frontend.Variable
}

// defineMerge recomputes every derived input to the public-input hash from the
// witness, asserts each equals the prover-supplied signal on publicHashInputs, fills
// the non-signal fields (per-input tree roots) publicHashInputs still needs, and
// returns publicHashInputs.Hash(api). ExternalDataHash/PrivateTxHash/Zone/ZoneProgramID
// are supplied by the caller (PrivateTxHash is asserted against the recomputed
// value); the remaining signals are bound to their derivations below.
func defineMerge(api frontend.API, witness mergeWitness, publicHashInputs publicInputHashInputs) (frontend.Variable, error) {
	// Owner hash: user_owner_hash = OwnerHash(pk_field(signing_pk),
	// user_nullifier_pk). pk_field has a unified P256/Ed25519 encoding (Poseidon
	// over the key's two 128-bit halves), so the prover supplies it directly and
	// state inclusion pins it to the committed leaf. Merge authorizes via the
	// nullifier secret, not a signature, so it recomputes no owner point (spec:
	// Zone-authority / merge instantiation).
	pkField := witness.ownerPkHash
	userOwnerHash := gadget.PoseidonHash(api, []frontend.Variable{pkField, witness.userNullifierPk})

	// Nullifier secret binding: nullifier_pk = Poseidon(nullifier_secret).
	nullifierPk := gadget.PoseidonHash(api, []frontend.Variable{witness.userNullifierSecret})
	api.AssertIsEqual(witness.userNullifierPk, nullifierPk)

	inputHashes := make([]frontend.Variable, len(witness.inputs))
	nullifiers := make([]frontend.Variable, len(witness.inputs))
	for i := range witness.inputs {
		inputHashes[i], nullifiers[i] = constrainInput(api, witness.inputs[i], userOwnerHash, witness.userNullifierSecret, witness.asset, publicHashInputs.UtxoTreeRoots[i], publicHashInputs.NullifierTreeRoots[i], publicHashInputs.Zone, publicHashInputs.ZoneProgramID)
	}
	assertDistinctNullifiers(api, witness.inputs, nullifiers)

	// Value conservation (single asset): dummies contribute 0 (amount pinned to 0
	// in constrainInput), so the sum over all slots equals the real total. The
	// merged output amount is assembled from this sum rather than witnessed, so
	// conservation holds by construction.
	sumInputs := frontend.Variable(0)
	for i := range witness.inputs {
		sumInputs = api.Add(sumInputs, witness.inputs[i].Amount)
	}

	outputHash := constrainOutput(api, witness.output, userOwnerHash, witness.asset, sumInputs, publicHashInputs.Zone, publicHashInputs.ZoneProgramID)

	addressHashes := make([]frontend.Variable, len(inputHashes))
	for i := range addressHashes {
		addressHashes[i] = frontend.Variable(0)
	}
	privateTxHash := transaction.PrivateTxHashCircuit(
		api,
		inputHashes,
		[]frontend.Variable{outputHash},
		addressHashes,
		publicHashInputs.ExternalDataHash,
	)
	api.AssertIsEqual(privateTxHash, publicHashInputs.PrivateTxHash)

	// Verifiable encryption of the merged output to the owner's viewing key.
	g := aes.NewAESGadget(api)
	ctHash, pkLo, pkHi := constrainEncryption(api, g, witness.txViewingSk, witness.userViewingPubkey, sumInputs, witness.asset, witness.output.Blinding)

	// pk_field(user_viewing_pk) over the same viewing point as the encryption
	// (constrainEncryption asserts it on-curve via p256.PointOnCurve). It is a
	// public input so SPP can check the encryption used the owner's registered
	// viewing key (spec Merge Proof public inputs).
	viewingPkField, err := transaction.P256PkFieldFromPointCircuit(api, *p256.ParsePublicKey(api, witness.userViewingPubkey))
	if err != nil {
		return nil, err
	}

	// Bind each prover-supplied hash input to its in-circuit derivation, so the
	// hash cannot be formed over forged values.
	for i := range nullifiers {
		api.AssertIsEqual(publicHashInputs.Nullifiers[i], nullifiers[i])
	}
	api.AssertIsEqual(publicHashInputs.OutputHash, outputHash)
	api.AssertIsEqual(publicHashInputs.UserSigningPkHash, pkField)
	api.AssertIsEqual(publicHashInputs.UserViewingPkHash, viewingPkField)
	api.AssertIsEqual(publicHashInputs.TxViewingPkLo, pkLo)
	api.AssertIsEqual(publicHashInputs.TxViewingPkHi, pkHi)
	api.AssertIsEqual(publicHashInputs.CtHash, ctHash)
	// The per-input tree roots are bound to the state-inclusion proofs inside
	// constrainInput above, so they need no assertion here.
	return publicHashInputs.Hash(api), nil
}

// publicInputHashInputs holds every value that feeds the merge PublicInputHash.
// It is embedded in the Circuit struct: the tagged signal fields are supplied by
// the prover and bound to their in-circuit derivations in defineMerge, while the
// gnark:"-" fields are not signals -- the tree roots are read from the Input
// witnesses and Zone/ZoneProgramID are the rail config. It is not the circuit's
// public input; that is the single PublicInputHash on the Circuit struct,
// asserted against Hash's output.
type publicInputHashInputs struct {
	// Nullifiers of all input slots (dummies included); folded into one field
	// via HashChain.
	Nullifiers []frontend.Variable
	// OutputHash is the merged output UTXO's leaf hash.
	OutputHash frontend.Variable

	PrivateTxHash    frontend.Variable
	ExternalDataHash frontend.Variable

	// Owner identity hashes, emitted only on the default rail (Zone == false).
	// UserSigningPkHash is pk_field(signing_pk); UserViewingPkHash is
	// pk_field(user_viewing_pk).
	UserSigningPkHash frontend.Variable
	UserViewingPkHash frontend.Variable

	// Ephemeral viewing pubkey limbs (lo, hi) and the ciphertext hash of the
	// verifiable encryption of the merged output.
	TxViewingPkLo frontend.Variable
	TxViewingPkHi frontend.Variable
	CtHash        frontend.Variable

	// UtxoTreeRoots / NullifierTreeRoots are the per-input roots, one entry per
	// slot, each folded via HashChain. constrainInput binds each real input's
	// state and nullifier inclusion proof to these supplied roots.
	UtxoTreeRoots      []frontend.Variable
	NullifierTreeRoots []frontend.Variable

	// Zone selects the zone rail: it swaps the owner-hash pair out of the hash
	// and appends ZoneProgramID at the end. Both are rail config, not signals:
	// the default rail pins ZoneProgramID to 0, the zone rail routes its
	// top-level ZoneProgramID signal in.
	Zone          bool              `gnark:"-"`
	ZoneProgramID frontend.Variable `gnark:"-"`
}

// Hash folds every input into the single PublicInputHash signal. The ordering
// matches spec Merge Proof public inputs and must stay in sync with the
// on-chain verifier.
func (publicHashInputs publicInputHashInputs) Hash(api frontend.API) frontend.Variable {
	fields := []frontend.Variable{
		gadget.HashChain(api, publicHashInputs.Nullifiers),
		publicHashInputs.OutputHash,
		gadget.HashChain(api, publicHashInputs.UtxoTreeRoots),
		gadget.HashChain(api, publicHashInputs.NullifierTreeRoots),
		publicHashInputs.PrivateTxHash,
		publicHashInputs.ExternalDataHash,
	}
	if !publicHashInputs.Zone {
		fields = append(fields, publicHashInputs.UserSigningPkHash, publicHashInputs.UserViewingPkHash)
	}
	fields = append(fields, publicHashInputs.TxViewingPkLo, publicHashInputs.TxViewingPkHi, publicHashInputs.CtHash)
	if publicHashInputs.Zone {
		fields = append(fields, publicHashInputs.ZoneProgramID)
	}
	return gadget.HashChain(api, fields)
}

func assertDistinctNullifiers(api frontend.API, inputs []Input, nullifiers []frontend.Variable) {
	for i := range inputs {
		for j := i + 1; j < len(inputs); j++ {
			iReal := api.IsZero(api.Sub(inputs[i].Domain, UtxoDomain))
			jReal := api.IsZero(api.Sub(inputs[j].Domain, UtxoDomain))
			bothReal := api.Mul(iReal, jReal)
			sameNullifier := api.IsZero(api.Sub(nullifiers[i], nullifiers[j]))
			api.AssertIsEqual(api.Mul(bothReal, sameNullifier), 0)
		}
	}
}

// allocInputSignals sizes the per-input signal slices so gnark allocates one
// signal per input slot.
func (p *publicInputHashInputs) allocInputSignals() {
	p.Nullifiers = make([]frontend.Variable, MergeInputs)
	p.UtxoTreeRoots = make([]frontend.Variable, MergeInputs)
	p.NullifierTreeRoots = make([]frontend.Variable, MergeInputs)
}

func validateLayout(numInputs int, inputs []Input) error {
	if numInputs != MergeInputs {
		return fmt.Errorf("merge: NumInputs must be %d, got %d", MergeInputs, numInputs)
	}
	if got := len(inputs); got != numInputs {
		return fmt.Errorf("merge: input count mismatch: got %d want %d", got, numInputs)
	}
	for i := range inputs {
		if got := len(inputs[i].StatePathElements); got != transaction.StateTreeHeight {
			return fmt.Errorf("merge: input %d state path height: got %d want %d", i, got, transaction.StateTreeHeight)
		}
		if got := len(inputs[i].NullifierLowPathElements); got != transaction.NullifierTreeHeight {
			return fmt.Errorf("merge: input %d nullifier path height: got %d want %d", i, got, transaction.NullifierTreeHeight)
		}
	}
	return nil
}
