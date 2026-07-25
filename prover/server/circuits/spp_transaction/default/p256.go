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

func (c *DefaultZoneP256Circuit) validateLayout() error {
	if err := shared.ValidateInputs(c.Shape.NInputs, c.Private.Inputs); err != nil {
		return err
	}
	checks := []struct {
		name      string
		got, want int
	}{
		{"nullifier", len(c.Public.Nullifiers), c.Shape.NInputs},
		{"output hash", len(c.Public.OutputHashes), c.Shape.NOutputs},
		{"utxo tree root", len(c.Public.UtxoTreeRoots), c.Shape.NInputs},
		{"nullifier tree root", len(c.Public.NullifierTreeRoots), c.Shape.NInputs},
		{"input owner pk hash", len(c.Public.InputOwnerPkHashes), c.Shape.NInputs},
		{"output owner pk hash", len(c.Public.OutputOwnerPkHashes), c.Shape.NOutputs},
		{"output", len(c.Private.Outputs), c.Shape.NOutputs},
		{"output nullifier pk", len(c.Private.OutputNullifierPks), c.Shape.NOutputs},
	}
	for _, check := range checks {
		if err := shared.ValidateLength(check.name, check.got, check.want); err != nil {
			return err
		}
	}
	return nil
}

func (c *DefaultZoneP256Circuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

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

	signers := shared.P256Signers(api, c.Private.Inputs, c.Public.InputOwnerPkHashes, p256)

	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	addressHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i, in := range c.Private.Inputs {
		in.Utxo.AssertInDefaultZone(api)
		signals := shared.InputSignals{
			Nullifier:         c.Public.Nullifiers[i],
			UtxoTreeRoot:      c.Public.UtxoTreeRoots[i],
			NullifierTreeRoot: c.Public.NullifierTreeRoots[i],
			SignerPk:          signers[i],
		}
		inputHashes[i], addressHashes[i] = shared.ConstrainInput(api, in, signals)
	}
	shared.AssertDistinctNullifiers(api, c.Public.Nullifiers)

	outputHashes := make([]frontend.Variable, c.Shape.NOutputs)
	for i, utxo := range c.Private.Outputs {
		outputHashes[i] = shared.ConstrainDefaultZoneOutput(
			api,
			utxo,
			c.Public.OutputHashes[i],
			c.Public.OutputOwnerPkHashes[i],
			c.Private.OutputNullifierPks[i],
			signers,
		)
	}

	shared.AssertBalanceConservation(
		api,
		shared.InputUtxos(c.Private.Inputs),
		c.Private.Outputs,
		c.Public.PublicAssets[:],
		c.Public.PublicAmounts[:],
	)

	api.AssertIsEqual(c.Public.ZoneProgramID, 0)

	privateTxHash := shared.PrivateTxHashCircuit(
		api,
		inputHashes,
		outputHashes,
		addressHashes,
		c.Public.ExternalDataHash,
	)
	api.AssertIsEqual(privateTxHash, c.Public.PrivateTxHash)

	api.AssertIsEqual(c.Public.PublicInputHash, c.publicInputHash(api))
	return nil
}

func (c *DefaultZoneP256Circuit) publicInputHash(api frontend.API) frontend.Variable {
	fields := []frontend.Variable{
		gadget.HashChain(api, c.Public.Nullifiers),
		gadget.HashChain(api, c.Public.OutputHashes),
		gadget.HashChain(api, c.Public.UtxoTreeRoots),
		gadget.HashChain(api, c.Public.NullifierTreeRoots),
		c.Public.PrivateTxHash,
		gadget.PoseidonHash(api, []frontend.Variable{c.Public.P256MessageHashLow, c.Public.P256MessageHashHigh}),
		c.Public.ExternalDataHash,
	}
	fields = append(fields, shared.PublicSlots(c.Public.PublicAssets, c.Public.PublicAmounts)...)
	fields = append(fields,
		c.Public.ZoneProgramID,
		c.Public.PayerPubkeyHash,
		gadget.HashChain(api, c.Public.InputOwnerPkHashes),
		gadget.HashChain(api, c.Public.OutputOwnerPkHashes),
		c.Public.P256SigningPkField,
	)
	return gadget.HashChain(api, fields)
}
