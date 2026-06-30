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

type Circuit struct {
	NumInputs int `gnark:"-"`

	Inputs []Input
	Output Output

	// Shared owner identity, one of two rails. P256Pub is the owner's P256 signing
	// pubkey witness (canonical x, y, parity); OwnerPkHash is the owner's pk_field.
	// OwnerPkHash == 0 selects the P256 path (P256-owned) and recomputes pk_field
	// from P256Pub; a non-zero value is the Ed25519 owner's pk_field and is used
	// directly (the P256 witness is then a dummy point).
	P256Pub             transaction.P256PublicKey
	OwnerPkHash         frontend.Variable
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

func (c *Circuit) Define(api frontend.API) error {
	if err := validateLayout(c.NumInputs, c.Inputs); err != nil {
		return err
	}
	publicInputHash, err := defineMerge(api, mergeSignals{
		inputs:              c.Inputs,
		output:              c.Output,
		p256Pub:             c.P256Pub,
		ownerPkHash:         c.OwnerPkHash,
		userNullifierPk:     c.UserNullifierPk,
		userNullifierSecret: c.UserNullifierSecret,
		txViewingSk:         c.TxViewingSk,
		userViewingPubkey:   c.UserViewingPubkey,
		externalDataHash:    c.ExternalDataHash,
		privateTxHash:       c.PrivateTxHash,
		zone:                false,
		zoneProgramID:       frontend.Variable(0),
	})
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.PublicInputHash, publicInputHash)
	return nil
}

type mergeSignals struct {
	inputs              []Input
	output              Output
	p256Pub             transaction.P256PublicKey
	ownerPkHash         frontend.Variable
	userNullifierPk     frontend.Variable
	userNullifierSecret frontend.Variable
	txViewingSk         frontend.Variable
	userViewingPubkey   [65]frontend.Variable
	externalDataHash    frontend.Variable
	privateTxHash       frontend.Variable
	zone                bool
	zoneProgramID       frontend.Variable
}

func defineMerge(api frontend.API, s mergeSignals) (frontend.Variable, error) {
	// Owner hash binding: user_owner_hash = OwnerHash(pk_field(signing_pk),
	// user_nullifier_pk). The pk_field is recomputed from the witnessed P256
	// point so the proof references no opaque owner.
	p256PkField, err := transaction.OwnerPkFieldFromPubkeyCircuit(api, s.p256Pub)
	if err != nil {
		return nil, err
	}
	isP256 := api.IsZero(s.ownerPkHash)
	pkField := api.Select(isP256, p256PkField, s.ownerPkHash)
	userOwnerHash := gadget.PoseidonHash(api, []frontend.Variable{pkField, s.userNullifierPk})

	// Nullifier secret binding: nullifier_pk = Poseidon(nullifier_secret).
	nullifierPk := gadget.PoseidonHash(api, []frontend.Variable{s.userNullifierSecret})
	api.AssertIsEqual(s.userNullifierPk, nullifierPk)

	outputAsset := s.output.Utxo.Asset

	inputHashes := make([]frontend.Variable, len(s.inputs))
	for i := range s.inputs {
		inputHashes[i] = constrainInput(api, s.inputs[i], userOwnerHash, s.userNullifierSecret, outputAsset, s.zone, s.zoneProgramID)
	}
	assertDistinctNullifiers(api, s.inputs)

	// Value conservation (single asset): dummies contribute 0 (amount pinned to 0
	// in constrainInput), so the sum over all slots equals the real total.
	sumInputs := frontend.Variable(0)
	for i := range s.inputs {
		sumInputs = api.Add(sumInputs, s.inputs[i].Utxo.Amount)
	}
	api.AssertIsEqual(sumInputs, s.output.Utxo.Amount)

	outputHash := constrainOutput(api, s.output, userOwnerHash, s.zone, s.zoneProgramID)

	addressHashes := make([]frontend.Variable, len(inputHashes))
	for i := range addressHashes {
		addressHashes[i] = frontend.Variable(0)
	}
	privateTxHash := transaction.PrivateTxHashCircuit(
		api,
		inputHashes,
		[]frontend.Variable{outputHash},
		addressHashes,
		s.externalDataHash,
	)
	api.AssertIsEqual(privateTxHash, s.privateTxHash)

	// Verifiable encryption of the merged output to the owner's viewing key.
	g := aes.NewAESGadget(api)
	ctHash, pkLo, pkHi := constrainEncryption(api, g, s.txViewingSk, s.userViewingPubkey, s.output)

	// pk_field(user_viewing_pk) over the same viewing point as the encryption
	// (constrainEncryption asserts it on-curve via p256.PointOnCurve). It is a
	// public input so SPP can check the encryption used the owner's registered
	// viewing key (spec Merge Proof public inputs).
	viewingPkField, err := transaction.P256PkFieldFromPointCircuit(api, *p256.ParsePublicKey(api, s.userViewingPubkey))
	if err != nil {
		return nil, err
	}

	return mergePublicInputHash(api, s, outputHash, pkField, viewingPkField, ctHash, pkLo, pkHi), nil
}

func mergePublicInputHash(api frontend.API, s mergeSignals, outputHash, userSigningPkHash, userViewingPkHash, ctHash, txViewingPkLo, txViewingPkHi frontend.Variable) frontend.Variable {
	fields := []frontend.Variable{
		gadget.HashChain(api, inputNullifiers(s.inputs)),
		outputHash,
		gadget.HashChain(api, inputUtxoRoots(s.inputs)),
		gadget.HashChain(api, inputNullifierTreeRoots(s.inputs)),
		s.privateTxHash,
		s.externalDataHash,
	}
	if !s.zone {
		fields = append(fields, userSigningPkHash, userViewingPkHash)
	}
	fields = append(fields, txViewingPkLo, txViewingPkHi, ctHash)
	if s.zone {
		fields = append(fields, s.zoneProgramID)
	}
	return gadget.HashChain(api, fields)
}

func assertDistinctNullifiers(api frontend.API, inputs []Input) {
	for i := range inputs {
		for j := i + 1; j < len(inputs); j++ {
			bothReal := api.Mul(api.Sub(1, inputs[i].IsDummy), api.Sub(1, inputs[j].IsDummy))
			sameNullifier := api.IsZero(api.Sub(inputs[i].Nullifier, inputs[j].Nullifier))
			api.AssertIsEqual(api.Mul(bothReal, sameNullifier), 0)
		}
	}
}

func inputNullifiers(inputs []Input) []frontend.Variable {
	out := make([]frontend.Variable, len(inputs))
	for i := range inputs {
		out[i] = inputs[i].Nullifier
	}
	return out
}

func inputUtxoRoots(inputs []Input) []frontend.Variable {
	out := make([]frontend.Variable, len(inputs))
	for i := range inputs {
		out[i] = inputs[i].UtxoTreeRoot
	}
	return out
}

func inputNullifierTreeRoots(inputs []Input) []frontend.Variable {
	out := make([]frontend.Variable, len(inputs))
	for i := range inputs {
		out[i] = inputs[i].NullifierTreeRoot
	}
	return out
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
