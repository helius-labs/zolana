package merge

import (
	"github.com/consensys/gnark/frontend"
)

type ZoneCircuit struct {
	NumInputs int `gnark:"-"`

	Inputs []Input
	Output Output

	// Asset is the single asset shared by every real input and the merged output.
	Asset frontend.Variable

	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable

	TxViewingSk       frontend.Variable
	UserViewingPubkey [65]frontend.Variable

	// publicInputHashInputs carries the prover-supplied inputs to the public-input
	// hash (see the Circuit struct). Its ZoneProgramID is rail config (gnark:"-");
	// the zone rail's top-level ZoneProgramID below is the actual signal, routed
	// into it in Define.
	publicInputHashInputs

	// ZoneProgramID is the zone rail's top-level signal: the zone program's
	// pk_field bound into every UTXO leaf and appended to the public-input hash.
	ZoneProgramID frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

func NewMergeZoneCircuit() *ZoneCircuit {
	c := &ZoneCircuit{
		NumInputs: MergeInputs,
		Inputs:    newInputs(),
	}
	c.allocInputSignals()
	c.Zone = true
	return c
}

func (c *ZoneCircuit) Define(api frontend.API) error {
	if err := validateLayout(c.NumInputs, c.Inputs); err != nil {
		return err
	}
	// Route the top-level ZoneProgramID signal into the hash config the embedded
	// struct carries.
	c.publicInputHashInputs.ZoneProgramID = c.ZoneProgramID
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
