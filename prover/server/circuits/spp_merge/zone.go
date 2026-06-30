package merge

import (
	"github.com/consensys/gnark/frontend"

	transaction "zolana/prover/circuits/spp_transaction"
)

type ZoneCircuit struct {
	NumInputs int `gnark:"-"`

	Inputs []Input
	Output Output

	P256Pub             transaction.P256PublicKey
	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable

	TxViewingSk       frontend.Variable
	UserViewingPubkey [65]frontend.Variable

	ExternalDataHash frontend.Variable
	PrivateTxHash    frontend.Variable
	ZoneProgramID    frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

func NewMergeZoneCircuit() *ZoneCircuit {
	c := &ZoneCircuit{
		NumInputs: MergeInputs,
		Inputs:    make([]Input, MergeInputs),
	}
	for i := range c.Inputs {
		c.Inputs[i].StatePathElements = make([]frontend.Variable, transaction.StateTreeHeight)
		c.Inputs[i].NullifierLowPathElements = make([]frontend.Variable, transaction.NullifierTreeHeight)
	}
	return c
}

func (c *ZoneCircuit) Define(api frontend.API) error {
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
		zone:                true,
		zoneProgramID:       c.ZoneProgramID,
	})
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.PublicInputHash, publicInputHash)
	return nil
}
