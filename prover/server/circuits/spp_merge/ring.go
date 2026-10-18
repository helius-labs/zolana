package merge

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
)

// Properties:
// 1. Anonymity - the owner of the merged UTXOs is not revealed.
// 2. Nonzero dummy nullifiers are indistinguishable from UTXO nullifiers;
// compact padding publishes 0.
// 3. Signatureless consolidation is intentional. The proof authenticates every
// input under the same owner and proves possession of that owner's nullifier
// secret. Application data is zero and the output remains owner-recoverable.
// 4. Balances are preserved.
// 5. Input and output utxos are owned by the same owner.
// 6. 1/many UTXOs to one UTXO
// 7. The output's amount and mint are published under a ciphertext the owner
// can decrypt without trusting its merger. Every other output field derives from the owner's keys,
// the first nullifier, and the public ring values, so the owner rebuilds the
// output from the merge transaction alone.

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
	// in the instruction/event. This public value is bound to the output
	// commitment, and every real input must carry the same hash. A merge has no
	// separate policy proof and cannot replace the authenticated ring state.
	OutputRingDataHash frontend.Variable
	RingProgramID      frontend.Variable
	// A merge reuses the owner's recovery registration. The record is bound to
	// the on-chain root and its key commitment to the secret used by the merge.
	MemberRegistryRoot       frontend.Variable
	RegisteredCiphertextHash frontend.Variable
	MemberRecord             registry.RecordOpening

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
	derived, err := tx.Constrain(api)
	if err != nil {
		return err
	}
	tx.AssertRingDataPreserved(api)
	api.AssertIsEqual(c.OutputRingDataHash, c.Output.RingDataHash)
	c.MemberRecord.AssertPresent(api, 1, c.MemberRegistryRoot, c.OwnerPkHash)
	api.AssertIsDifferent(c.RegisteredCiphertextHash, 0)
	api.AssertIsEqual(c.MemberRecord.EscrowKey,
		gadget.PoseidonHash(api, []frontend.Variable{c.UserNullifierPk, c.RegisteredCiphertextHash}))

	fields := c.CommonPublicInputs.Prefix(api)
	fields = append(fields, c.OutputRingDataHash, c.RingProgramID, c.MemberRegistryRoot)
	// Both rails end with the salt, then the output ciphertext.
	fields = append(fields, c.OutputCiphertextSalt)
	fields = append(fields, derived.OutputCiphertext...)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, fields))
	return nil
}
