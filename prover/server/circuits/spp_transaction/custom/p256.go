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

func (c *CustomZoneP256Circuit) validateLayout() error {
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
		{"output", len(c.Private.Outputs), c.Shape.NOutputs},
	}
	for _, check := range checks {
		if err := shared.ValidateLength(check.name, check.got, check.want); err != nil {
			return err
		}
	}
	return nil
}

func (c *CustomZoneP256Circuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

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

	signers := shared.P256Signers(api, c.Private.Inputs, c.Public.InputOwnerPkHashes, p256)

	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	addressHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i, in := range c.Private.Inputs {
		shared.AssertWhen(api, in.IsUtxo(api), shared.CheckZoneMemberOrFree(api, in.Utxo, c.Public.ZoneProgramID))
		signals := shared.InputSignals{
			Nullifier:         c.Public.Nullifiers[i],
			UtxoTreeRoot:      c.Public.UtxoTreeRoots[i],
			NullifierTreeRoot: c.Public.NullifierTreeRoots[i],
			SignerPk:          signers[i],
		}
		inputHashes[i], addressHashes[i] = shared.ConstrainInput(api, in, signals)
	}
	shared.AssertDistinctNullifiers(api, c.Public.Nullifiers)

	signerOwners := shared.SignerOwners(api, c.Private.Inputs)
	outputHashes := make([]frontend.Variable, c.Shape.NOutputs)
	for i, utxo := range c.Private.Outputs {
		shared.AssertWhen(api, utxo.IsUtxo(api), shared.CheckZoneMemberOrFree(api, utxo, c.Public.ZoneProgramID))
		outputHashes[i] = shared.ConstrainCustomZoneOutput(api, utxo, c.Public.OutputHashes[i], signerOwners)
	}

	shared.AssertBalanceConservation(
		api,
		shared.InputUtxos(c.Private.Inputs),
		c.Private.Outputs,
		c.Public.PublicAssets[:],
		c.Public.PublicAmounts[:],
	)

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

func (c *CustomZoneP256Circuit) publicInputHash(api frontend.API) frontend.Variable {
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
	)
	return gadget.HashChain(api, fields)
}
