package merge

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
)

type RingCircuit struct {
	NumInputs int `gnark:"-"`

	Inputs []Input
	Output Output

	MintChunks [mergeshared.MintChunkCount]frontend.Variable

	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable

	mergeshared.CommonPublicInputs

	OutputRingDataHash frontend.Variable
	RingProgramID      frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

func NewMergeRingCircuit(n int) *RingCircuit {
	return &RingCircuit{
		NumInputs:          n,
		Inputs:             mergeshared.NewInputs(n),
		CommonPublicInputs: mergeshared.NewCommonPublicInputs(n),
	}
}

func (c *RingCircuit) transaction() mergeshared.Transaction {
	return mergeshared.Transaction{
		Inputs:              c.Inputs,
		Output:              c.Output,
		MintChunks:          c.MintChunks,
		OwnerPkHash:         c.OwnerPkHash,
		UserNullifierPk:     c.UserNullifierPk,
		UserNullifierSecret: c.UserNullifierSecret,
		Public:              c.CommonPublicInputs,
		RingProgramID:       c.RingProgramID,
	}
}

func (c *RingCircuit) Define(api frontend.API) error {
	tx := c.transaction()
	if err := tx.ValidateLayout(c.NumInputs); err != nil {
		return err
	}
	api.AssertIsDifferent(c.RingProgramID, 0)
	tx.OutputAmount = mergeshared.RangeCheckedAmount(api, c.Inputs)
	tx.Constrain(api)
	api.AssertIsEqual(c.OutputRingDataHash, c.Output.RingDataHash)

	fields := c.CommonPublicInputs.Prefix(api)
	fields = append(fields, c.OutputRingDataHash, c.RingProgramID)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, fields))
	return nil
}
