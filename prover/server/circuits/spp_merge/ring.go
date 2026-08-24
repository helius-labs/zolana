package merge

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
)

// Properties:
// 1. Anonymity - the owner of the merged UTXOs is not revealed.
// 2. Dummy public inputs are indistinguishable from UTXO public inputs.
// 3. No signatures are enforced in the program or circuit.
// 4. Balances are preserved.
// 5. Input and output utxos are owned by the same owner.
// 6. 1/many UTXOs to one UTXO
// 7. The output UTXO is derived completely deterministically from the
// input UTXOs so that the owner can derive it without decrypting the transaction cipher text.

type RingCircuit struct {
	NumInputs int `gnark:"-"`

	Inputs []Input
	Output Output

	Asset frontend.Variable

	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable
	PrivateTxBlinding   frontend.Variable

	mergeshared.CommonPublicInputs

	// OutputRingDataHash is the ring-data hash the calling ring program carries
	// in the instruction/event; asserting it against Output.RingDataHash binds
	// the carried value to Output.Utxo.RingDataHash. Ring state stays under the
	// ring proof; this proof only binds the hash.
	OutputRingDataHash frontend.Variable
	RingProgramID      frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

func NewMergeRingCircuit() *RingCircuit {
	return &RingCircuit{
		NumInputs:          MergeInputs,
		Inputs:             mergeshared.NewInputs(),
		CommonPublicInputs: mergeshared.NewCommonPublicInputs(),
	}
}

func (c *RingCircuit) transaction() mergeshared.Transaction {
	return mergeshared.Transaction{
		Inputs:              c.Inputs,
		Output:              c.Output,
		Asset:               c.Asset,
		OwnerPkHash:         c.OwnerPkHash,
		UserNullifierPk:     c.UserNullifierPk,
		UserNullifierSecret: c.UserNullifierSecret,
		PrivateTxBlinding:   c.PrivateTxBlinding,
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
	if _, err := tx.Constrain(api); err != nil {
		return err
	}
	api.AssertIsEqual(c.OutputRingDataHash, c.Output.RingDataHash)

	fields := c.CommonPublicInputs.Prefix(api)
	fields = append(fields, c.OutputRingDataHash, c.RingProgramID)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, fields))
	return nil
}
