package merge

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
)

// Properties:
// 1. Anonymity - the owner of the merged UTXOs is not revealed.
// 2. Nonzero dummy nullifiers are indistinguishable from UTXO nullifiers;
// compact padding publishes 0.
// 3. No signatures are enforced in the program or circuit.
// 4. Balances are preserved.
// 5. Input and output utxos are owned by the same owner.
// 6. 1/many UTXOs to one UTXO
// 7. Every output field but the amount and mint is derived from the owner's
// keys, the first nullifier, and the public ring values. The output ciphertext
// a ring merge carries is not bound by this proof: SPP publishes it unverified,
// and a ring that needs it recoverable enforces it in its own program.

type RingCircuit struct {
	NumInputs int `gnark:"-"`

	Inputs []Input
	Output Output

	MintChunks [2]frontend.Variable

	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable

	mergeshared.CommonPublicInputs

	// OutputRingDataHash is the ring-data hash the calling ring program carries
	// in the instruction/event; asserting it against Output.RingDataHash binds
	// the carried value to Output.Utxo.RingDataHash. Ring state stays under the
	// ring proof; this proof only binds the hash.
	OutputRingDataHash frontend.Variable
	RingProgramID      frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

// NewMergeRingCircuit allocates the policy-ring merge circuit for n input
// slots. One proving system exists per supported count; Define rejects any
// other.
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
	if _, err := tx.Constrain(api); err != nil {
		return err
	}
	api.AssertIsEqual(c.OutputRingDataHash, c.Output.RingDataHash)

	fields := c.CommonPublicInputs.Prefix(api)
	fields = append(fields, c.OutputRingDataHash, c.RingProgramID)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, fields))
	return nil
}
