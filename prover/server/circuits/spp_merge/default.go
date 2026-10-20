// Package merge implements the default and policy-ring SPP merge circuits.
package merge

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
)

// Properties:
// 1. Confidentiality - Input and output UTXO owner pubkeys are public inputs.
// 2. Nonzero dummy nullifiers are indistinguishable from UTXO nullifiers;
// compact padding publishes 0.
// 3. No owner signature is enforced; cache insertion requires its write authority to sign.
// 4. Balances are preserved.
// 5. Input and output utxos are owned by the same owner.
// 6. 1/many UTXOs to one UTXO
// 7. The output's amount and mint are published under a ciphertext only the
// owner can decrypt, and every other output field is derived from the owner's keys
// and the first nullifier, so the owner rebuilds the output from the merge
// transaction alone, even when the merger folded in a note the owner never saw.
// The ciphertext uses the scheme the owner registered; the program checks the
// scheme and selects this circuit's key by it.

type (
	Input  = mergeshared.Input
	Output = mergeshared.Output
)

const (
	UtxoDomain  = mergeshared.UtxoDomain
	DummyDomain = mergeshared.DummyDomain
)

// Circuit is the default-ring merge rail. It publishes the owner's signing
// pk_field and nullifier public key in addition to the common preimage.
type Circuit struct {
	NumInputs int `gnark:"-"`

	Inputs []Input
	Output Output

	MintChunks [2]frontend.Variable

	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable

	mergeshared.CommonPublicInputs

	UserSigningPkHash frontend.Variable

	// OutputCiphertextSalt is the per-proof pad nonce of the PoseidonCtrV1
	// output ciphertext. It is 16 bytes of instruction data, so it is canonical
	// without a range check.
	OutputCiphertextSalt frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

// NewMergeCircuit allocates the default-rail merge circuit for n input slots.
// One proving system exists per supported count; Define rejects any other.
func NewMergeCircuit(n int) *Circuit {
	return &Circuit{
		NumInputs:          n,
		Inputs:             mergeshared.NewInputs(n),
		CommonPublicInputs: mergeshared.NewCommonPublicInputs(n),
	}
}

func (c *Circuit) transaction() mergeshared.Transaction {
	return mergeshared.Transaction{
		Inputs:              c.Inputs,
		Output:              c.Output,
		MintChunks:          c.MintChunks,
		OwnerPkHash:         c.OwnerPkHash,
		UserNullifierPk:     c.UserNullifierPk,
		UserNullifierSecret: c.UserNullifierSecret,
		Public:              c.CommonPublicInputs,
		RingProgramID:       frontend.Variable(0),
	}
}

func (c *Circuit) Define(api frontend.API) error {
	tx := c.transaction()
	if err := tx.ValidateLayout(c.NumInputs); err != nil {
		return err
	}

	assertDefaultRing(api, tx.Inputs, tx.Output)
	derived, err := tx.Constrain(api)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.UserSigningPkHash, c.OwnerPkHash)

	fields := c.CommonPublicInputs.Prefix(api)
	fields = append(fields, c.UserSigningPkHash, c.UserNullifierPk)
	fields = append(fields, c.outputEncryption(api, tx, derived)...)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, fields))
	return nil
}

// outputEncryption encrypts the merged output's amount and mint chunks under
// the PoseidonCtrV1 scheme and returns the public-input-hash tail it binds: the
// salt, then the ciphertext. A new scheme is a new circuit (and key) with its
// own tail.
func (c *Circuit) outputEncryption(
	api frontend.API,
	tx mergeshared.Transaction,
	derived mergeshared.Derived,
) []frontend.Variable {
	ciphertext := mergeshared.MergeOutputCiphertext(
		api,
		tx.UserNullifierSecret,
		derived.FirstNullifier,
		c.OutputCiphertextSalt,
		derived.OutputAmount,
		tx.MintChunks,
	)
	return append([]frontend.Variable{c.OutputCiphertextSalt}, ciphertext...)
}

// assertDefaultRing pins ring data to zero for every real input and for the
// always-real output. Dummy input ring data remains free, matching the existing
// arity-hiding convention.
func assertDefaultRing(api frontend.API, inputs []Input, output Output) {
	for _, input := range inputs {
		isUtxo := api.IsZero(api.Sub(input.Domain, UtxoDomain))
		abstractor.CallVoid(api, gadget.AssertZeroWhen{
			Cond: isUtxo,
			V:    input.RingDataHash,
		})
	}
	api.AssertIsEqual(output.RingDataHash, 0)
}
