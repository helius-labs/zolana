package defaultzone

import (
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
)

// DefaultZoneP256Public is the confidential P256 rail's public-input-hash
// preimage, declared in preimage order. Only PublicInputHash is a gnark-public
// wire; the rest is protocol-public because SPP recomputes the hash from it.
type DefaultZoneP256Public struct {
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
	PublicAssets        [shared.NPublicSlots]frontend.Variable
	PublicAmounts       [shared.NPublicSlots]frontend.Variable
	ZoneProgramID       frontend.Variable
	PayerPubkeyHash     frontend.Variable
	InputOwnerPkHashes  []frontend.Variable
	OutputOwnerPkHashes []frontend.Variable
	// P256SigningPkField is the shared P256 signing key's pk_field; public in
	// the default-zone variants so SPP fills the P256-owned input owner entries.
	P256SigningPkField frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

type DefaultZoneP256Private struct {
	Inputs  []shared.Input
	Outputs []shared.UtxoCircuitFields
	// OutputNullifierPks are the witnessed nullifier pubkeys that recompute
	// each output owner from its public tag.
	OutputNullifierPks []frontend.Variable
	P256Pub            shared.P256PublicKey
	P256Sig            shared.P256Signature
}

type DefaultZoneP256Circuit struct {
	Shape   shared.Shape `gnark:"-"`
	Public  DefaultZoneP256Public
	Private DefaultZoneP256Private
}

func NewDefaultZoneP256Circuit(shape shared.Shape) (*DefaultZoneP256Circuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	return &DefaultZoneP256Circuit{
		Shape: shape,
		Public: DefaultZoneP256Public{
			Nullifiers:          make([]frontend.Variable, shape.NInputs),
			OutputHashes:        make([]frontend.Variable, shape.NOutputs),
			UtxoTreeRoots:       make([]frontend.Variable, shape.NInputs),
			NullifierTreeRoots:  make([]frontend.Variable, shape.NInputs),
			InputOwnerPkHashes:  make([]frontend.Variable, shape.NInputs),
			OutputOwnerPkHashes: make([]frontend.Variable, shape.NOutputs),
		},
		Private: DefaultZoneP256Private{
			Inputs:             shared.NewInputs(shape.NInputs),
			Outputs:            make([]shared.UtxoCircuitFields, shape.NOutputs),
			OutputNullifierPks: make([]frontend.Variable, shape.NOutputs),
		},
	}, nil
}

// transaction views this rail's witness as the shared transaction, with the P256
// preimage slots this rail actually carries: the message digest field and the
// shared signing key.
func (c *DefaultZoneP256Circuit) transaction(api frontend.API) shared.Transaction {
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
			gadget.HashChain(api, c.Public.OutputOwnerPkHashes),
			c.Public.P256SigningPkField,
		},
	}
}

func (c *DefaultZoneP256Circuit) Define(api frontend.API) error {
	tx := c.transaction(api)
	if err := tx.ValidateLayout(
		shared.LengthCheck{Name: "input owner pk hash", Got: len(c.Public.InputOwnerPkHashes), Want: c.Shape.NInputs},
		shared.LengthCheck{Name: "output owner pk hash", Got: len(c.Public.OutputOwnerPkHashes), Want: c.Shape.NOutputs},
		shared.LengthCheck{Name: "output nullifier pk", Got: len(c.Private.OutputNullifierPks), Want: c.Shape.NOutputs},
	); err != nil {
		return err
	}

	shared.AssertDefaultZone(api, tx.Inputs, tx.Outputs)
	api.AssertIsEqual(c.Public.ZoneProgramID, 0)
	shared.AssertOutputOwnerTags(api, tx.Outputs, c.Public.OutputOwnerPkHashes, c.Private.OutputNullifierPks)

	p256, err := shared.NewP256Signer(
		api,
		c.Private.P256Pub,
		c.Private.P256Sig,
		c.Public.P256MessageHashLow,
		c.Public.P256MessageHashHigh,
		c.Public.P256SigningPkField,
	)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.Public.P256SigningPkField, p256.PkField)

	signers := shared.P256Signers(api, tx.Inputs, c.Public.InputOwnerPkHashes, p256)
	return tx.Constrain(api, signers, signers.ContainsEach(api, c.Public.OutputOwnerPkHashes))
}
