package customring

import (
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// Properties:
// 1. Public: ring program, public asset transfers, nullifiers, and output UTXO hashes.
// 2. Private: input and output UTXO owners, UTXO amounts, and UTXO assets.
// 3. The Solana program requires the ring authority signature; the ring may enforce additional authorization.
// 4. All real input and output UTXOs belong to the ring.
// 5. Address inputs are not allowed.
// 6. Dummy slots are indistinguishable from real UTXO slots.
// 7. Input nullifiers are distinct and balances are preserved.

type CustomRingAuthorityPublic struct {
	Nullifiers         []frontend.Variable
	OutputHashes       []frontend.Variable
	UtxoTreeRoots      []frontend.Variable
	NullifierTreeRoots []frontend.Variable
	PrivateTxHash      frontend.Variable
	ExternalDataHash   frontend.Variable
	PublicAssets       [shared.NPublicSlots]frontend.Variable
	PublicAmounts      [shared.NPublicSlots]frontend.Variable
	RingProgramID      frontend.Variable
	SignerPkHashes     []frontend.Variable
	AllowDummyInputs   frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

type CustomRingAuthorityPrivate struct {
	Inputs             []shared.Input
	InputOwnerPkHashes []frontend.Variable
	Outputs            []shared.UtxoCircuitFields
	OutputBlindingSeed frontend.Variable
	PrivateTxBlinding  frontend.Variable
}

type CustomRingAuthorityCircuit struct {
	Shape   shared.Shape `gnark:"-"`
	Public  CustomRingAuthorityPublic
	Private CustomRingAuthorityPrivate
}

func NewCustomRingAuthorityCircuit(shape shared.Shape) (*CustomRingAuthorityCircuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	return &CustomRingAuthorityCircuit{
		Shape: shape,
		Public: CustomRingAuthorityPublic{
			Nullifiers:         make([]frontend.Variable, shape.NInputs),
			OutputHashes:       make([]frontend.Variable, shape.NOutputs),
			UtxoTreeRoots:      make([]frontend.Variable, shape.NInputs),
			NullifierTreeRoots: make([]frontend.Variable, shape.NInputs),
			SignerPkHashes:     make([]frontend.Variable, 1),
		},
		Private: CustomRingAuthorityPrivate{
			Inputs:             shared.NewInputs(shape.NInputs),
			InputOwnerPkHashes: make([]frontend.Variable, shape.NInputs),
			Outputs:            make([]shared.UtxoCircuitFields, shape.NOutputs),
		},
	}, nil
}

func (c *CustomRingAuthorityCircuit) transaction(api frontend.API) shared.Transaction {
	return shared.Transaction{
		Shape:              c.Shape,
		Nullifiers:         c.Public.Nullifiers,
		OutputHashes:       c.Public.OutputHashes,
		UtxoTreeRoots:      c.Public.UtxoTreeRoots,
		NullifierTreeRoots: c.Public.NullifierTreeRoots,
		Inputs:             c.Private.Inputs,
		Outputs:            c.Private.Outputs,
		OutputBlindingSeed: c.Private.OutputBlindingSeed,
		PrivateTxHash:      c.Public.PrivateTxHash,
		PrivateTxBlinding:  c.Private.PrivateTxBlinding,
		ExternalDataHash:   c.Public.ExternalDataHash,
		PublicAssets:       c.Public.PublicAssets,
		PublicAmounts:      c.Public.PublicAmounts,
		RingProgramID:      c.Public.RingProgramID,
		SignerPkHashChain:  gadget.RightHashChain(api, c.Public.SignerPkHashes),
		AllowDummyInputs:   c.Public.AllowDummyInputs,
		PublicInputHash:    c.Public.PublicInputHash,
	}
}

func (c *CustomRingAuthorityCircuit) Define(api frontend.API) error {
	tx := c.transaction(api)
	if err := tx.ValidateLayout(
		shared.LengthCheck{Name: "signer pk hash", Got: len(c.Public.SignerPkHashes), Want: 1},
		shared.LengthCheck{Name: "input owner pk hash", Got: len(c.Private.InputOwnerPkHashes), Want: c.Shape.NInputs},
	); err != nil {
		return err
	}

	// Ring authority cannot create addresses.
	for _, input := range tx.Inputs {
		api.AssertIsDifferent(input.Utxo.Domain, shared.AddressDomain)
	}

	shared.AssertRingMember(api, tx.Inputs, tx.Outputs, c.Public.RingProgramID)
	api.AssertIsDifferent(c.Public.RingProgramID, 0)

	signers := shared.EddsaOnlySigners(api, tx.Inputs, c.Private.InputOwnerPkHashes)
	signerOwners := shared.SignerOwners(api, tx.Inputs)
	return tx.Constrain(api, signers, signerOwners.ContainsEach(api, shared.OutputOwners(tx.Outputs)))
}
