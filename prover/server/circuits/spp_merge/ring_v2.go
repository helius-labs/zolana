package merge

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
)

// RingV2Circuit under a zero nullifier secret has no spend secret, so SPP's signer
// check on PublishedOwner is the merge authorization.
type RingV2Circuit struct {
	NumInputs int `gnark:"-"`

	Inputs []Input
	Output Output

	MintChunks [2]frontend.Variable

	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable
	MergeSeed           frontend.Variable

	mergeshared.CommonPublicInputs

	OutputRingDataHash frontend.Variable
	RingProgramID      frontend.Variable
	PublishedOwner     frontend.Variable
	// OutputCiphertextSalt is 16 bytes of instruction data, canonical without a
	// range check.
	OutputCiphertextSalt frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

func NewMergeRingV2Circuit(n int) *RingV2Circuit {
	return &RingV2Circuit{
		NumInputs:          n,
		Inputs:             mergeshared.NewInputs(n),
		CommonPublicInputs: mergeshared.NewCommonPublicInputs(n),
	}
}

func (c *RingV2Circuit) Define(api frontend.API) error {
	tx := mergeshared.Transaction{
		Inputs:              c.Inputs,
		Output:              c.Output,
		MintChunks:          c.MintChunks,
		OwnerPkHash:         c.OwnerPkHash,
		UserNullifierPk:     c.UserNullifierPk,
		UserNullifierSecret: c.UserNullifierSecret,
		Public:              c.CommonPublicInputs,
		RingProgramID:       c.RingProgramID,
	}
	if err := tx.ValidateLayout(c.NumInputs); err != nil {
		return err
	}
	api.AssertIsDifferent(c.RingProgramID, 0)

	// Only secret zero opens Poseidon(0), absent a collision.
	zeroKey := api.IsZero(c.UserNullifierSecret)
	seed := api.Select(zeroKey, c.MergeSeed, c.UserNullifierSecret)
	api.AssertIsDifferent(seed, 0)

	// A zero owner under a zero key would publish zero and drop SPP's signer check.
	api.AssertIsEqual(api.Mul(zeroKey, api.IsZero(c.OwnerPkHash)), 0)
	api.AssertIsEqual(c.PublishedOwner, api.Mul(zeroKey, c.OwnerPkHash))

	derived := tx.ConstrainSeeded(api, seed)
	api.AssertIsEqual(c.OutputRingDataHash, c.Output.RingDataHash)

	fields := c.CommonPublicInputs.Prefix(api)
	fields = append(fields, c.OutputRingDataHash, c.RingProgramID, c.PublishedOwner, c.OutputCiphertextSalt)
	fields = append(fields, mergeshared.MergeOutputCiphertext(
		api,
		seed,
		derived.FirstNullifier,
		c.OutputCiphertextSalt,
		derived.OutputAmount,
		tx.MintChunks,
	)...)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, fields))
	return nil
}
