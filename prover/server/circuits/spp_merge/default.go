// Package merge implements the default and policy-ring SPP merge circuits.
package merge

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
	ve "zolana/prover/circuits/verifiable-encryption"
)

// Properties:
// 1. Confidentiality - Input and output UTXO owner pubkeys are public inputs.
// 2. Nonzero dummy nullifiers are indistinguishable from UTXO nullifiers;
// compact padding publishes 0.
// 3. No owner signature is enforced; cache insertion requires its write authority to sign.
// 4. Balances are preserved.
// 5. Input and output utxos are owned by the same owner.
// 6. 1/many UTXOs to one UTXO
// 7. The output UTXO blinding derives from the envelope shared secret, so the
// owner recovers the output by decrypting the envelope with its viewing key.

type (
	Input  = mergeshared.Input
	Output = mergeshared.Output
)

const (
	UtxoDomain  = mergeshared.UtxoDomain
	DummyDomain = mergeshared.DummyDomain
)

// Circuit is the default-ring merge rail. It publishes the owner's signing
// pk_field and nullifier public key in addition to the common preimage.
type Circuit struct {
	NumInputs int `gnark:"-"`

	Inputs []Input
	Output Output

	MintChunks [mergeshared.MintChunkCount]frontend.Variable

	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable

	ViewingPk   [ve.UncompressedPointBytes]frontend.Variable
	EphemeralSk [ve.ScalarBytes]frontend.Variable

	mergeshared.CommonPublicInputs

	UserSigningPkHash frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

// NewMergeCircuit allocates the default-rail merge circuit for n input slots.
// One proving system exists per supported count; Define rejects any other.
func NewMergeCircuit(n int) *Circuit {
	return &Circuit{
		NumInputs:          n,
		Inputs:             mergeshared.NewInputs(n),
		CommonPublicInputs: mergeshared.NewCommonPublicInputs(n),
	}
}

func (c *Circuit) Define(api frontend.API) error {
	tx := mergeshared.Transaction{
		Inputs:              c.Inputs,
		Output:              c.Output,
		MintChunks:          c.MintChunks,
		OwnerPkHash:         c.OwnerPkHash,
		UserNullifierPk:     c.UserNullifierPk,
		UserNullifierSecret: c.UserNullifierSecret,
		Public:              c.CommonPublicInputs,
		RingProgramID:       frontend.Variable(0),
	}
	if err := tx.ValidateLayout(c.NumInputs); err != nil {
		return err
	}

	amount, amountBytes := mergeshared.AmountBytes(api, c.Inputs)
	encrypted := ve.Envelope{
		SecretTag:   mergeshared.MergeSecretTag,
		KdfInfo:     mergeshared.MergeKdfInfo,
		EphemeralSk: c.EphemeralSk,
		RecipientPk: c.ViewingPk,
		Plaintext:   mergeshared.MergePlaintext(api, amountBytes, c.MintChunks),
		// The published first nullifier is unique per accepted merge, so a
		// reused ephemeral key repeats neither the keystream nor the output leaf.
		Context: c.Nullifiers[0],
	}.Encrypt(api)
	tx.OutputAmount = amount
	tx.OutputBlinding = mergeshared.MergeDerivedBlinding(api, encrypted.SharedSecret)

	assertDefaultRing(api, tx.Inputs, tx.Output)
	tx.Constrain(api)
	api.AssertIsEqual(c.UserSigningPkHash, c.OwnerPkHash)

	envelope := mergeshared.EnvelopePublicElements(api, encrypted)
	fields := c.CommonPublicInputs.Prefix(api)
	fields = append(fields, c.UserSigningPkHash, c.UserNullifierPk)
	fields = append(fields, envelope[:]...)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, fields))
	return nil
}

// assertDefaultRing pins ring data to zero for every real input and for the
// always-real output. Dummy input ring data remains free, matching the existing
// arity-hiding convention.
func assertDefaultRing(api frontend.API, inputs []Input, output Output) {
	for _, input := range inputs {
		isUtxo := api.IsZero(api.Sub(input.Domain, UtxoDomain))
		abstractor.CallVoid(api, gadget.AssertZeroWhen{
			Cond: isUtxo,
			V:    input.RingDataHash,
		})
	}
	api.AssertIsEqual(output.RingDataHash, 0)
}
