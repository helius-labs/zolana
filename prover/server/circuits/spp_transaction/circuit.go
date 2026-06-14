package transaction

import (
	"fmt"

	"light/light-prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

type Circuit struct {
	Shape Shape `gnark:"-"`
	// RequiresP256 picks the rail at compile time. True: include the emulated
	// P256 ECDSA gadget (most of the constraints) for P256 owners. False:
	// Solana-only, no gadget (~7x smaller), every real input must be
	// Solana-owned (SolanaOwnerPkHash != 0).
	RequiresP256 bool `gnark:"-"`

	Inputs  []Input
	Outputs []Output

	ExternalDataHash frontend.Variable
	P256Pub          P256PublicKey
	P256Sig          P256Signature

	PrivateTxHash        frontend.Variable
	P256MessageHash      frontend.Variable
	PublicSolAmount      frontend.Variable
	PublicSplAmount      frontend.Variable
	PublicSplAssetPubkey frontend.Variable
	ProgramIDHashchain   frontend.Variable
	PayerPubkeyHash      frontend.Variable
	DataHash             frontend.Variable
	ZoneDataHash         frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

type Input struct {
	Utxo              UtxoCircuitFields
	IsDummy           frontend.Variable
	StatePathElements []frontend.Variable
	StatePathIndex    frontend.Variable

	NullifierLowValue        frontend.Variable
	NullifierNextValue       frontend.Variable
	NullifierLowPathElements []frontend.Variable
	NullifierLowPathIndex    frontend.Variable

	UtxoTreeRoot      frontend.Variable
	NullifierTreeRoot frontend.Variable
	Nullifier         frontend.Variable

	SolanaOwnerPkHash frontend.Variable
	NullifierSecret   frontend.Variable
}

type Output struct {
	Utxo    UtxoCircuitFields
	IsDummy frontend.Variable
	Hash    frontend.Variable
}

// NewCircuit builds the P256-capable transaction circuit (includes the ECDSA
// gadget). Use NewSolanaCircuit for the cheaper Solana-only rail.
func NewCircuit(shape Shape) (*Circuit, error) {
	return newCircuit(shape, true)
}

// NewSolanaCircuit builds the Solana-only transaction circuit: it omits the
// emulated-P256 gadget (~7x fewer constraints) and requires every real input to
// be Solana-owned.
func NewSolanaCircuit(shape Shape) (*Circuit, error) {
	return newCircuit(shape, false)
}

func newCircuit(shape Shape, requiresP256 bool) (*Circuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	c := &Circuit{
		Shape:        shape,
		RequiresP256: requiresP256,
		Inputs:       make([]Input, shape.NInputs),
		Outputs:      make([]Output, shape.NOutputs),
	}
	for i := 0; i < shape.NInputs; i++ {
		c.Inputs[i].StatePathElements = make([]frontend.Variable, StateTreeHeight)
		c.Inputs[i].NullifierLowPathElements = make([]frontend.Variable, NullifierTreeHeight)
	}
	return c, nil
}

// 1. Validate layout
//
// 2. create nullifier pubkeys
//
// 3. Verify p256 signature
//
//  4. Inputs:
//     4.1. create utxo hashes
//     4.2. create nullifiers
//     4.3. verify inclusion proof
//     4.4. verify nullifier non inclusion proof
//     4.4. verify every nullifier is unique
//
//  5. Outputs:
//     5.1. create output utxo hashes
//
// 6. check private transaction hash
//
// 7. check public inputs hash
func (c *Circuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

	// Ownership
	env := spendEnv{requiresP256: c.RequiresP256}
	if c.RequiresP256 {
		ownerKeyHash, err := P256PkFieldFromPubkeyCircuit(api, c.P256Pub)
		if err != nil {
			return err
		}
		p256Message, err := p256MessageHashToP256Fr(api, c.P256MessageHash)
		if err != nil {
			return err
		}
		env.p256PkField = ownerKeyHash
		env.p256SigValid = c.P256Pub.IsValid(
			api,
			sw_emulated.GetCurveParams[emulated.P256Fp](),
			p256Message,
			&c.P256Sig,
		)
	} else {
		// Solana-only rail: no P256 gadget. Pin the message hash to 0 and set
		// p256SigValid to a constant — constrainInput forces every real input
		// Solana-owned, so the P256 checks never fire.
		api.AssertIsEqual(c.P256MessageHash, 0)
		env.p256PkField = frontend.Variable(0)
		env.p256SigValid = frontend.Variable(1)
		// TODO: remove the commitment and make the proof flexible in the program
		// The P256 gadget adds a bsb22 commitment the on-chain Groth16Verifier
		// expects. The Solana rail has no gadget, so add one explicit commitment
		// to keep the same proof format and verifier.
		committer, ok := api.(frontend.Committer)
		if !ok {
			return fmt.Errorf("spp: frontend does not support commitments")
		}
		if _, err := committer.Commit(c.PublicInputHash); err != nil {
			return err
		}
	}
	// Inputs
	// TODO: move this into constrainInput
	nullifierPks := make([]frontend.Variable, c.Shape.NInputs)
	for i := 0; i < c.Shape.NInputs; i++ {
		nullifierPks[i] = abstractor.Call(api, NullifierPkGadget{
			NullifierSecret: c.Inputs[i].NullifierSecret,
		})
	}
	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i := 0; i < c.Shape.NInputs; i++ {
		inputHashes[i] = constrainInput(api, c.Inputs[i], nullifierPks[i], env)
	}
	c.assertDistinctNullifiers(api)
	// Outputs
	OutputHashes := make([]frontend.Variable, c.Shape.NOutputs)
	for i := 0; i < c.Shape.NOutputs; i++ {
		OutputHashes[i] = constrainOutput(api, c.Outputs[i])
	}

	// Sumcheck
	assertBalanceConservation(
		api,
		c.inputUtxos(),
		c.outputUtxos(),
		c.PublicSolAmount,
		c.PublicSplAmount,
		c.PublicSplAssetPubkey,
	)

	// Default transact has no program/zone authorization: these tx-level fields
	// must be zero (SPP reconstructs them as zero on-chain). Zone flows set them
	// via zone_transact.
	api.AssertIsEqual(c.ProgramIDHashchain, 0)
	api.AssertIsEqual(c.DataHash, 0)
	api.AssertIsEqual(c.ZoneDataHash, 0)

	privateTxHash := PrivateTxHashCircuit(
		api,
		inputHashes,
		OutputHashes,
		c.ExternalDataHash,
	)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	api.AssertIsEqual(c.PublicInputHash, c.publicInputHash(api))
	return nil
}

func (c *Circuit) publicInputHash(api frontend.API) frontend.Variable {
	return gadget.HashChain(api, []frontend.Variable{
		gadget.HashChain(api, c.InputNullifiers()),
		gadget.HashChain(api, c.OutputHashes()),
		gadget.HashChain(api, c.InputUtxoRoots()),
		gadget.HashChain(api, c.InputNullifierTreeRoots()),
		c.PrivateTxHash,
		c.P256MessageHash,
		c.ExternalDataHash,
		c.PublicSolAmount,
		c.PublicSplAmount,
		c.PublicSplAssetPubkey,
		c.ProgramIDHashchain,
		c.PayerPubkeyHash,
		c.DataHash,
		c.ZoneDataHash,
		gadget.HashChain(api, c.InputSolanaOwnerPkHashes()),
	})
}

func (c *Circuit) InputSolanaOwnerPkHashes() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].SolanaOwnerPkHash
	}
	return out
}

func (c *Circuit) inputUtxos() []UtxoCircuitFields {
	out := make([]UtxoCircuitFields, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].Utxo
	}
	return out
}

func (c *Circuit) outputUtxos() []UtxoCircuitFields {
	out := make([]UtxoCircuitFields, len(c.Outputs))
	for i := range c.Outputs {
		out[i] = c.Outputs[i].Utxo
	}
	return out
}

func (c *Circuit) InputNullifiers() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].Nullifier
	}
	return out
}

func (c *Circuit) OutputHashes() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Outputs))
	for i := range c.Outputs {
		out[i] = c.Outputs[i].Hash
	}
	return out
}

func (c *Circuit) InputUtxoRoots() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].UtxoTreeRoot
	}
	return out
}

func (c *Circuit) InputNullifierTreeRoots() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].NullifierTreeRoot
	}
	return out
}

func (c *Circuit) validateLayout() error {
	in, out := c.Shape.NInputs, c.Shape.NOutputs
	if len(c.Inputs) != in {
		return fmt.Errorf("spp: input count mismatch: got %d want %d", len(c.Inputs), in)
	}
	if len(c.Outputs) != out {
		return fmt.Errorf("spp: output count mismatch: got %d want %d", len(c.Outputs), out)
	}

	for i := 0; i < in; i++ {
		input := c.Inputs[i]
		if got := len(input.StatePathElements); got != StateTreeHeight {
			return fmt.Errorf("spp: input %d state path height: got %d want %d", i, got, StateTreeHeight)
		}
		if got := len(input.NullifierLowPathElements); got != NullifierTreeHeight {
			return fmt.Errorf("spp: input %d nullifier path height: got %d want %d", i, got, NullifierTreeHeight)
		}
	}
	return nil
}
