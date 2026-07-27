// Package merge implements the default and policy-zone SPP merge circuits.
package merge

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
)

// Properties:
// 1. Confidentiality - Input and output UTXO owner pubkeys are public inputs.
// 2. Dummy public inputs are indistinguishable from UTXO public inputs.
// 3. No signatures are enforced in the program or circuit.
// 4. Balances are preserved.
// 5. Input and output utxos are owned by the same owner.
// 6. 1/many UTXOs to one UTXO
// 7. The output UTXO is derived completely deterministically from the
// input UTXOs so that the owner can derive it without decrypting the transaction cipher text.

type (
	Input  = mergeshared.Input
	Output = mergeshared.Output
)

const (
	MergeInputs = mergeshared.MergeInputs
	UtxoDomain  = mergeshared.UtxoDomain
	DummyDomain = mergeshared.DummyDomain
)

// Circuit is the default-zone merge rail. It publishes the owner's signing
// pk_field in addition to the common merge public-input-hash preimage.
type Circuit struct {
	NumInputs int `gnark:"-"`

	Inputs []Input
	Output Output

	Asset frontend.Variable

	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable

	mergeshared.CommonPublicInputs

	UserSigningPkHash frontend.Variable

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
	if _, err := tx.Constrain(api); err != nil {
		return err
	}
	api.AssertIsEqual(c.UserSigningPkHash, c.OwnerPkHash)

	fields := c.CommonPublicInputs.Prefix(api)
	fields = append(fields, c.UserSigningPkHash)
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
