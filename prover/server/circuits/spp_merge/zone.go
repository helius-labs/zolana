package merge

import (
	"github.com/consensys/gnark/frontend"

	transaction "zolana/prover/circuits/spp_transaction"
)

// ZoneCircuit is the policy-zone merge proof (merge_zone): the CPI analog of the
// default merge for UTXOs owned by a policy zone. It runs the identical merge
// logic, but every real input and the merged output must carry zone_program_id ==
// ZoneProgramID (no zero exemption), so the proof consolidates only UTXOs already
// owned by the CPI-calling zone and preserves that ownership on the output.
// zone_data is left free for the zone program's own logic. ZoneProgramID is a
// public input so SPP binds it from the calling zone_config.
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

// NewMergeZoneCircuit builds the policy-zone merge circuit for the fixed
// 8-in / 1-out shape.
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
