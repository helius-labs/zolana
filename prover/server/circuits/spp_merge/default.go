// Package merge implements the default and policy-zone SPP merge circuits.
package merge

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
)

// Root aliases preserve the circuit API consumed by the prover package.
type (
	Input  = mergeshared.Input
	Output = mergeshared.Output
)

const (
	MergeInputs       = mergeshared.MergeInputs
	UtxoDomain        = mergeshared.UtxoDomain
	DummyDomain       = mergeshared.DummyDomain
	MergePlaintextLen = mergeshared.MergePlaintextLen
)

// Circuit is the default-zone merge rail. It publishes the owner's signing and
// viewing pk_fields in addition to the common merge public-input-hash preimage.
type Circuit struct {
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

	UserSigningPkHash frontend.Variable
	UserViewingPkHash frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

func NewMergeCircuit() *Circuit {
	return &Circuit{
		NumInputs:          MergeInputs,
		Inputs:             mergeshared.NewInputs(),
		CommonPublicInputs: mergeshared.NewCommonPublicInputs(),
	}
}

func (c *Circuit) transaction() mergeshared.Transaction {
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
		ZoneProgramID:       frontend.Variable(0),
	}
}

func (c *Circuit) Define(api frontend.API) error {
	tx := c.transaction()
	if err := tx.ValidateLayout(c.NumInputs); err != nil {
		return err
	}

	assertDefaultZone(api, tx.Inputs, tx.Output)
	derived, err := tx.Constrain(api)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.UserSigningPkHash, derived.OwnerPkHash)
	api.AssertIsEqual(c.UserViewingPkHash, derived.ViewingPkHash)

	fields := c.CommonPublicInputs.Prefix(api)
	fields = append(fields, c.UserSigningPkHash, c.UserViewingPkHash)
	fields = append(fields, c.CommonPublicInputs.EncryptionTail()...)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, fields))
	return nil
}

// assertDefaultZone pins zone data to zero for every real input and for the
// always-real output. Dummy input zone data remains free, matching the existing
// arity-hiding convention.
func assertDefaultZone(api frontend.API, inputs []Input, output Output) {
	for _, input := range inputs {
		isUtxo := api.IsZero(api.Sub(input.Domain, UtxoDomain))
		abstractor.CallVoid(api, gadget.AssertZeroWhen{
			Cond: isUtxo,
			V:    input.ZoneDataHash,
		})
	}
	api.AssertIsEqual(output.ZoneDataHash, 0)
}
