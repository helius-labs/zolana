package merge

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
)

// ZoneCircuit is the policy-zone merge rail. Owner identity stays private; the
// zone program is appended to the common merge public-input-hash preimage.
type ZoneCircuit struct {
	NumInputs int `gnark:"-"`

	Inputs []Input
	Output Output

	Asset frontend.Variable

	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable

	TxViewingSk       frontend.Variable
	UserViewingPubkey [65]frontend.Variable

	mergeshared.CommonPublicInputs

	ZoneProgramID frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

func NewMergeZoneCircuit() *ZoneCircuit {
	return &ZoneCircuit{
		NumInputs:          MergeInputs,
		Inputs:             mergeshared.NewInputs(),
		CommonPublicInputs: mergeshared.NewCommonPublicInputs(),
	}
}

func (c *ZoneCircuit) transaction() mergeshared.Transaction {
	return mergeshared.Transaction{
		Inputs:              c.Inputs,
		Output:              c.Output,
		Asset:               c.Asset,
		OwnerPkHash:         c.OwnerPkHash,
		UserNullifierPk:     c.UserNullifierPk,
		UserNullifierSecret: c.UserNullifierSecret,
		TxViewingSk:         c.TxViewingSk,
		UserViewingPubkey:   c.UserViewingPubkey,
		Public:              c.CommonPublicInputs,
		ZoneProgramID:       c.ZoneProgramID,
	}
}

func (c *ZoneCircuit) Define(api frontend.API) error {
	tx := c.transaction()
	if err := tx.ValidateLayout(c.NumInputs); err != nil {
		return err
	}
	if _, err := tx.Constrain(api); err != nil {
		return err
	}

	fields := c.CommonPublicInputs.Prefix(api)
	fields = append(fields, c.CommonPublicInputs.EncryptionTail()...)
	fields = append(fields, c.ZoneProgramID)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, fields))
	return nil
}
