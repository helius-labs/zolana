package customzone

import (
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// CustomZoneP256Public is the anonymous zone P256 rail's public-input-hash
// preimage. P256-owned entries route on the 0 sentinel, so no signing key is
// published; output owners stay private (no output owner tags).
type CustomZoneP256Public struct {
	Nullifiers         []frontend.Variable
	OutputHashes       []frontend.Variable
	UtxoTreeRoots      []frontend.Variable
	NullifierTreeRoots []frontend.Variable
	PrivateTxHash      frontend.Variable
	// P256 ECDSA message digest (full SHA-256) carried as two big-endian
	// 128-bit limbs: a 256-bit value does not fit in one BN254 element.
	P256MessageHashLow  frontend.Variable
	P256MessageHashHigh frontend.Variable
	ExternalDataHash    frontend.Variable
	// PublicAssets/PublicAmounts are the uniform public movement slots: a
	// signed net flow per asset (SOL is an ordinary asset id). Idle slots are
	// pinned to (0, 0) by AssertBalanceConservation.
	PublicAssets       [shared.NPublicSlots]frontend.Variable
	PublicAmounts      [shared.NPublicSlots]frontend.Variable
	ZoneProgramID      frontend.Variable
	PayerPubkeyHash    frontend.Variable
	InputOwnerPkHashes []frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

type CustomZoneP256Private struct {
	Inputs  []shared.Input
	Outputs []shared.UtxoCircuitFields
	P256Pub shared.P256PublicKey
	P256Sig shared.P256Signature
}

type CustomZoneP256Circuit struct {
	Shape   shared.Shape `gnark:"-"`
	Public  CustomZoneP256Public
	Private CustomZoneP256Private
}

func NewCustomZoneP256Circuit(shape shared.Shape) (*CustomZoneP256Circuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	return &CustomZoneP256Circuit{
		Shape: shape,
		Public: CustomZoneP256Public{
			Nullifiers:         make([]frontend.Variable, shape.NInputs),
			OutputHashes:       make([]frontend.Variable, shape.NOutputs),
			UtxoTreeRoots:      make([]frontend.Variable, shape.NInputs),
			NullifierTreeRoots: make([]frontend.Variable, shape.NInputs),
			InputOwnerPkHashes: make([]frontend.Variable, shape.NInputs),
		},
		Private: CustomZoneP256Private{
			Inputs:  shared.NewInputs(shape.NInputs),
			Outputs: make([]shared.UtxoCircuitFields, shape.NOutputs),
		},
	}, nil
}

// transaction views this rail's witness as the shared transaction. Output owners
// stay private here, so the preimage tail publishes only the input owner-tag
// chain, and no shared signing key is published: P256-owned entries route on the
// 0 sentinel instead.
func (c *CustomZoneP256Circuit) transaction(api frontend.API) shared.Transaction {
	return shared.Transaction{
		Shape:              c.Shape,
		Nullifiers:         c.Public.Nullifiers,
		OutputHashes:       c.Public.OutputHashes,
		UtxoTreeRoots:      c.Public.UtxoTreeRoots,
		NullifierTreeRoots: c.Public.NullifierTreeRoots,
		Inputs:             c.Private.Inputs,
		Outputs:            c.Private.Outputs,
		PrivateTxHash:      c.Public.PrivateTxHash,
		ExternalDataHash:   c.Public.ExternalDataHash,
		PublicAssets:       c.Public.PublicAssets,
		PublicAmounts:      c.Public.PublicAmounts,
		ZoneProgramID:      c.Public.ZoneProgramID,
		PayerPubkeyHash:    c.Public.PayerPubkeyHash,
		PublicInputHash:    c.Public.PublicInputHash,
		PreimageTail: []frontend.Variable{
			gadget.PoseidonHash(api, []frontend.Variable{
				c.Public.P256MessageHashLow,
				c.Public.P256MessageHashHigh,
			}),
			gadget.HashChain(api, c.Public.InputOwnerPkHashes),
		},
	}
}

func (c *CustomZoneP256Circuit) Define(api frontend.API) error {
	tx := c.transaction(api)
	if err := tx.ValidateLayout(
		shared.LengthCheck{Name: "input owner pk hash", Got: len(c.Public.InputOwnerPkHashes), Want: c.Shape.NInputs},
	); err != nil {
		return err
	}

	shared.AssertZoneMemberOrFree(api, tx.Inputs, tx.Outputs, c.Public.ZoneProgramID)

	p256, err := shared.NewP256Signer(
		api,
		c.Private.P256Pub,
		c.Private.P256Sig,
		c.Public.P256MessageHashLow,
		c.Public.P256MessageHashHigh,
		frontend.Variable(0),
	)
	if err != nil {
		return err
	}

	signers := shared.P256Signers(api, tx.Inputs, c.Public.InputOwnerPkHashes, p256)
	signerOwners := shared.SignerOwners(api, tx.Inputs)
	return tx.Constrain(api, signers, signerOwners.ContainsEach(api, shared.OutputOwners(tx.Outputs)))
}
