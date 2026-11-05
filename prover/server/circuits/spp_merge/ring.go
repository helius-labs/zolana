package merge

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
)

// Properties:
// 1. Anonymity - under a nonzero nullifier secret the owner of the merged UTXOs
// is not revealed.
// 2. Nonzero dummy nullifiers are indistinguishable from UTXO nullifiers;
// compact padding publishes 0.
// 3. Under a zero nullifier secret SPP requires the signer whose hashed key is
// PublishedOwner.
// 4. Balances are preserved.
// 5. Input and output utxos are owned by the same owner.
// 6. 1/many UTXOs to one UTXO
// 7. Every output field but the amount and mint is derived from the seed, the
// first nullifier, and the public ring values. The amount and mint are
// published under a ciphertext keyed the same way.

type RingCircuit struct {
	NumInputs int `gnark:"-"`

	Inputs []Input
	Output Output

	MintChunks [2]frontend.Variable

	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable
	MergeSeed           frontend.Variable

	mergeshared.CommonPublicInputs

	// OutputRingDataHash is the ring-data hash the calling ring program carries
	// in the instruction/event; asserting it against Output.RingDataHash binds
	// the carried value to Output.Utxo.RingDataHash. Ring state stays under the
	// ring proof; this proof only binds the hash.
	OutputRingDataHash frontend.Variable
	RingProgramID      frontend.Variable
	PublishedOwner     frontend.Variable
	// A 16-byte salt is canonical without a range check.
	OutputCiphertextSalt frontend.Variable

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

	// Only secret zero opens Poseidon(0), absent a collision.
	zeroKey := api.IsZero(c.UserNullifierSecret)
	seed := api.Select(zeroKey, c.MergeSeed, c.UserNullifierSecret)
	api.AssertIsDifferent(seed, 0)

	// A zero owner under a zero key would publish zero and drop SPP's signer check.
	api.AssertIsEqual(api.Mul(zeroKey, api.IsZero(c.OwnerPkHash)), 0)
	api.AssertIsEqual(c.PublishedOwner, api.Mul(zeroKey, c.OwnerPkHash))

	derived, err := tx.Constrain(api, seed)
	if err != nil {
		return err
	}
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
