package merge

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/records"
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
// a ring merge carries is bound by this proof.

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
	// The ring program takes the root from its registry history, zero on an anonymous merge.
	MemberRegistryRoot       frontend.Variable
	RegisteredCiphertextHash frontend.Variable
	MemberRecord             records.QuadRecordOpening
	// Anonymous is the ring program's 0 or 1 from its RingMode, its own merge proof discloses the output key.
	Anonymous frontend.Variable

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
	// 1. The merged notes belong to a ring, never to the default ring's id 0.
	api.AssertIsDifferent(c.RingProgramID, 0)
	// 2. Every input and the output share one owner and asset, the output sums the inputs.
	derived, err := tx.Constrain(api)
	if err != nil {
		return err
	}
	// 3. A merge never rewrites ring state, every real input carries the output's ring data hash.
	tx.AssertRingDataPreserved(api)
	api.AssertIsEqual(c.OutputRingDataHash, c.Output.RingDataHash)
	// 4. In escrow mode the owner's record lies under the root, an owner 0 opens the sentinel and fails the escrow.
	escrowed := api.Sub(1, c.Anonymous)
	c.MemberRecord.AssertPresent(api, escrowed, c.MemberRegistryRoot, c.OwnerPkHash)
	// 5. The record escrows the nullifier key the inputs spend under, so the auditor recovers the merged owner.
	escrowKey := records.EscrowKey(api, c.UserNullifierPk, c.RegisteredCiphertextHash)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: escrowed, A: c.MemberRecord.EscrowKey, B: escrowKey})

	// 6. Prefix, ring tail, salt, then the output ciphertext, mirrored by MergeProof::public_input_hash in
	// programs/shielded-pool/src/instructions/merge/verify.rs.
	fields := c.CommonPublicInputs.Prefix(api)
	fields = append(fields, c.OutputRingDataHash, c.RingProgramID, c.MemberRegistryRoot, c.Anonymous)
	fields = append(fields, c.OutputCiphertextSalt)
	fields = append(fields, derived.OutputCiphertext...)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, fields))
	return nil
}
