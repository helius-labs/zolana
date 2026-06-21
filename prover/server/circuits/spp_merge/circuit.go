// Package merge implements the SPP Merge Proof (spec: Merge Proof - Merge ZK
// Proof). It consolidates up to 8 input UTXOs of a single owner and single asset
// into one output UTXO of the same owner, asset, and total amount, and
// verifiably encrypts the merged output to the owner's viewing key. The proof
// takes no wallet secret beyond the values a sync delegate holds; ownership is
// proven by recomputing the owner hash from the witnessed P256 signing point and
// pinning the shared nullifier secret.
package merge

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction"
	"zolana/prover/circuits/verifiable-encryption/aes"
	"zolana/prover/circuits/verifiable-encryption/p256"
)

// MergeShape is the single supported merge shape: 8 inputs, 1 output. Fewer than
// 8 real inputs use dummy slots.
const (
	MergeInputs = 8
	UtxoDomain  = transaction.UtxoDomain
)

type Input struct {
	Utxo    transaction.UtxoCircuitFields
	IsDummy frontend.Variable

	StatePathElements []frontend.Variable
	StatePathIndex    frontend.Variable

	NullifierLowValue        frontend.Variable
	NullifierNextValue       frontend.Variable
	NullifierLowPathElements []frontend.Variable
	NullifierLowPathIndex    frontend.Variable

	UtxoTreeRoot      frontend.Variable
	NullifierTreeRoot frontend.Variable
	Nullifier         frontend.Variable
}

type Output struct {
	Utxo transaction.UtxoCircuitFields
	Hash frontend.Variable
}

// Circuit is the merge proof. The merged output is always real (no dummy output
// slot). Ownership is uniform: every real input and the output share
// user_owner_hash, recomputed in-circuit from the witnessed P256 signing point
// and the shared nullifier pubkey.
type Circuit struct {
	NumInputs int `gnark:"-"`

	Inputs []Input
	Output Output

	// Shared owner identity. P256Pub is the owner's P256 signing pubkey witness
	// (canonical x, y, parity) used to recompute pk_field(user_signing_pk).
	P256Pub             transaction.P256PublicKey
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable

	// Verifiable encryption witnesses. TxViewingSk is the ephemeral P-256 scalar
	// (a BN254-range field element); UserViewingPubkey is the owner's viewing
	// pubkey as a 65-byte uncompressed point (0x04 || x || y).
	TxViewingSk       frontend.Variable
	UserViewingPubkey [65]frontend.Variable

	ExternalDataHash frontend.Variable
	PrivateTxHash    frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

// NewMergeCircuit builds the merge circuit for the fixed 8-in / 1-out shape.
func NewMergeCircuit() *Circuit {
	c := &Circuit{
		NumInputs: MergeInputs,
		Inputs:    make([]Input, MergeInputs),
	}
	for i := range c.Inputs {
		c.Inputs[i].StatePathElements = make([]frontend.Variable, transaction.StateTreeHeight)
		c.Inputs[i].NullifierLowPathElements = make([]frontend.Variable, transaction.NullifierTreeHeight)
	}
	return c
}

// Define runs the merge proof:
//
//  1. validate layout
//  2. recompute user_owner_hash from the P256 point; pin the nullifier secret
//  3. inputs: inclusion, ownership/asset uniformity, nullifier derivation and
//     non-inclusion, cleanliness (inputs.go)
//  4. value conservation: sum(inputs) == output
//  5. output: cleanliness, owner binding, output_utxo_hash (outputs.go)
//  6. private_tx_hash
//  7. verifiable encryption of the merged output (encryption.go)
//  8. public input hash
func (c *Circuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

	// Owner hash binding: user_owner_hash = OwnerHash(pk_field(signing_pk),
	// user_nullifier_pk). The pk_field is recomputed from the witnessed P256
	// point so the proof references no opaque owner.
	pkField, err := transaction.P256PkFieldFromPubkeyCircuit(api, c.P256Pub)
	if err != nil {
		return err
	}
	userOwnerHash := gadget.PoseidonHash(api, []frontend.Variable{pkField, c.UserNullifierPk})

	// Nullifier secret binding: nullifier_pk = Poseidon(nullifier_secret).
	nullifierPk := gadget.PoseidonHash(api, []frontend.Variable{c.UserNullifierSecret})
	api.AssertIsEqual(c.UserNullifierPk, nullifierPk)

	outputAsset := c.Output.Utxo.Asset

	inputHashes := make([]frontend.Variable, c.NumInputs)
	for i := range c.Inputs {
		inputHashes[i] = constrainInput(api, c.Inputs[i], userOwnerHash, c.UserNullifierSecret, outputAsset)
	}
	c.assertDistinctNullifiers(api)

	// Value conservation (single asset): dummies contribute 0 (amount pinned to 0
	// in constrainInput), so the sum over all slots equals the real total.
	sumInputs := frontend.Variable(0)
	for i := range c.Inputs {
		sumInputs = api.Add(sumInputs, c.Inputs[i].Utxo.Amount)
	}
	api.AssertIsEqual(sumInputs, c.Output.Utxo.Amount)

	outputHash := constrainOutput(api, c.Output, userOwnerHash)

	privateTxHash := transaction.PrivateTxHashCircuit(
		api,
		inputHashes,
		[]frontend.Variable{outputHash},
		c.ExternalDataHash,
	)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	// Verifiable encryption of the merged output to the owner's viewing key.
	g := aes.NewAESGadget(api)
	ctHash, pkLo, pkHi := c.constrainEncryption(api, g)

	// pk_field(user_viewing_pk) over the same viewing point as the encryption
	// (constrainEncryption asserts it on-curve via p256.PointOnCurve). It is a
	// public input so SPP can check the encryption used the owner's registered
	// viewing key (spec Merge Proof public inputs).
	viewingPkField, err := transaction.P256PkFieldFromPointCircuit(api, *p256.ParsePublicKey(api, c.UserViewingPubkey))
	if err != nil {
		return err
	}

	// pkField (the hashed owner signing pubkey) is a public input so the owner
	// identity is committed in the public transcript; together with the owner's
	// own nullifier_pk it lets the owner recompute user_owner_hash without the
	// owner being carried in the ciphertext.
	api.AssertIsEqual(c.PublicInputHash, c.publicInputHash(api, outputHash, pkField, viewingPkField, ctHash, pkLo, pkHi))
	return nil
}

func (c *Circuit) publicInputHash(api frontend.API, outputHash, userSigningPkHash, userViewingPkHash, ctHash, txViewingPkLo, txViewingPkHi frontend.Variable) frontend.Variable {
	return gadget.HashChain(api, []frontend.Variable{
		gadget.HashChain(api, c.inputNullifiers()),
		outputHash,
		gadget.HashChain(api, c.inputUtxoRoots()),
		gadget.HashChain(api, c.inputNullifierTreeRoots()),
		c.PrivateTxHash,
		c.ExternalDataHash,
		userSigningPkHash,
		userViewingPkHash,
		txViewingPkLo,
		txViewingPkHi,
		ctHash,
	})
}

func (c *Circuit) assertDistinctNullifiers(api frontend.API) {
	for i := range c.Inputs {
		for j := i + 1; j < len(c.Inputs); j++ {
			bothReal := api.Mul(api.Sub(1, c.Inputs[i].IsDummy), api.Sub(1, c.Inputs[j].IsDummy))
			sameNullifier := api.IsZero(api.Sub(c.Inputs[i].Nullifier, c.Inputs[j].Nullifier))
			api.AssertIsEqual(api.Mul(bothReal, sameNullifier), 0)
		}
	}
}

func (c *Circuit) inputNullifiers() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].Nullifier
	}
	return out
}

func (c *Circuit) inputUtxoRoots() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].UtxoTreeRoot
	}
	return out
}

func (c *Circuit) inputNullifierTreeRoots() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].NullifierTreeRoot
	}
	return out
}

func (c *Circuit) validateLayout() error {
	if c.NumInputs != MergeInputs {
		return fmt.Errorf("merge: NumInputs must be %d, got %d", MergeInputs, c.NumInputs)
	}
	if got := len(c.Inputs); got != c.NumInputs {
		return fmt.Errorf("merge: input count mismatch: got %d want %d", got, c.NumInputs)
	}
	for i := range c.Inputs {
		if got := len(c.Inputs[i].StatePathElements); got != transaction.StateTreeHeight {
			return fmt.Errorf("merge: input %d state path height: got %d want %d", i, got, transaction.StateTreeHeight)
		}
		if got := len(c.Inputs[i].NullifierLowPathElements); got != transaction.NullifierTreeHeight {
			return fmt.Errorf("merge: input %d nullifier path height: got %d want %d", i, got, transaction.NullifierTreeHeight)
		}
	}
	return nil
}
