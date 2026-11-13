package customring

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// The authority statement with outputs that may leave to the default ring under
// published owner tags.
type CustomRingAuthorityExitCircuit struct {
	CachedInputs shared.CachedInputs

	Shape   shared.Shape `gnark:"-"`
	Public  CustomRingAuthorityExitPublic
	Private CustomRingAuthorityExitPrivate
}

type CustomRingAuthorityExitPublic struct {
	CustomRingAuthorityPublic
	PublishedOutputOwnerPkHashes []frontend.Variable
}

type CustomRingAuthorityExitPrivate struct {
	CustomRingAuthorityPrivate
	OutputOwnerPkHashes []frontend.Variable
	OutputNullifierPks  []frontend.Variable
}

func NewCustomRingAuthorityExitCircuit(shape shared.Shape) (*CustomRingAuthorityExitCircuit, error) {
	authority, err := NewCustomRingAuthorityCircuit(shape)
	if err != nil {
		return nil, err
	}
	return &CustomRingAuthorityExitCircuit{
		CachedInputs: shared.NewCachedInputs(shape.NInputs),
		Shape:        shape,
		Public: CustomRingAuthorityExitPublic{
			CustomRingAuthorityPublic:    authority.Public,
			PublishedOutputOwnerPkHashes: make([]frontend.Variable, shape.NOutputs),
		},
		Private: CustomRingAuthorityExitPrivate{
			CustomRingAuthorityPrivate: authority.Private,
			OutputOwnerPkHashes:        make([]frontend.Variable, shape.NOutputs),
			OutputNullifierPks:         make([]frontend.Variable, shape.NOutputs),
		},
	}, nil
}

func (c *CustomRingAuthorityExitCircuit) authority() CustomRingAuthorityCircuit {
	return CustomRingAuthorityCircuit{
		Shape:   c.Shape,
		Public:  c.Public.CustomRingAuthorityPublic,
		Private: c.Private.CustomRingAuthorityPrivate,
	}
}

func (c *CustomRingAuthorityExitCircuit) Define(api frontend.API) error {
	authority := c.authority()
	tx := authority.transaction(api)
	tx.CachedInputs = &c.CachedInputs
	published := c.Public.PublishedOutputOwnerPkHashes
	tx.PreimageTail = []frontend.Variable{gadget.RightHashChain4(api, published)}
	owners, nullifierPks := c.Private.OutputOwnerPkHashes, c.Private.OutputNullifierPks
	if err := tx.ValidateLayout(append(
		authority.lengthChecks(),
		shared.LengthCheck{Name: "output owner pk hash", Got: len(owners), Want: c.Shape.NOutputs},
		shared.LengthCheck{Name: "output nullifier pk", Got: len(nullifierPks), Want: c.Shape.NOutputs},
		shared.LengthCheck{Name: "published output owner pk hash", Got: len(published), Want: c.Shape.NOutputs},
	)...); err != nil {
		return err
	}

	if err := shared.AssertOutputOwnerTags(api, tx.Outputs, owners, nullifierPks); err != nil {
		return err
	}
	if err := shared.AssertExitOwnersNamed(api, tx.Outputs, owners); err != nil {
		return err
	}
	if err := shared.AssertPublishedOutputOwners(api, tx.Outputs, owners, published); err != nil {
		return err
	}
	if err := shared.AssertMaskedDummyOutputTags(
		api,
		tx.Outputs,
		tx.OutputIsCompact,
		published,
		shared.Signers(c.Public.SignerPkHashes),
	); err != nil {
		return err
	}
	return authority.constrain(api, tx, func() {
		shared.AssertRingInputsFreeOutputs(api, tx.Inputs, tx.Outputs, c.Public.RingProgramID)
	})
}
