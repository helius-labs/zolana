package transaction

import (
	"fmt"

	"light/light-prover/prover/spp/circuit/gadget"
	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

type Circuit struct {
	Shape protocol.Shape `gnark:"-"`
	// RequiresP256 selects the ownership rail at compile time. When true the
	// circuit includes the emulated-P256 ECDSA gadget (~86% of constraints) for
	// P256/passkey owners. When false it is a Solana-only circuit: the gadget is
	// omitted (~7x smaller) and every real input must be Solana-owned. Both
	// rails are homogeneous because the circuit enforces a single owner.
	RequiresP256 bool `gnark:"-"`

	Inputs  []Input
	Outputs []Output

	ExternalDataHash frontend.Variable
	ExpiryUnixTs     frontend.Variable
	NullifierSecret  frontend.Variable
	P256Pub          gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	P256Sig          gnarkecdsa.Signature[emulated.P256Fr]

	PrivateTxHash        frontend.Variable
	P256MessageHash      frontend.Variable
	PublicSolAmount      frontend.Variable
	PublicSplAmount      frontend.Variable
	PublicSplAssetPubkey frontend.Variable
	ProgramIDHashchain   frontend.Variable
	SolanaPubkeyHash     frontend.Variable
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

	UtxoTreeRoot  frontend.Variable
	NullifierRoot frontend.Variable
	Nullifier     frontend.Variable
	SolanaPkHash  frontend.Variable
}

type Output struct {
	Utxo    UtxoCircuitFields
	IsDummy frontend.Variable
	Hash    frontend.Variable
}

// NewCircuit builds the P256-capable transaction circuit (includes the ECDSA
// gadget). Use NewSolanaCircuit for the cheaper Solana-only rail.
func NewCircuit(shape protocol.Shape) (*Circuit, error) {
	return newCircuit(shape, true)
}

// NewSolanaCircuit builds the Solana-only transaction circuit: it omits the
// emulated-P256 gadget (~7x fewer constraints) and requires every real input to
// be Solana-owned.
func NewSolanaCircuit(shape protocol.Shape) (*Circuit, error) {
	return newCircuit(shape, false)
}

func newCircuit(shape protocol.Shape, requiresP256 bool) (*Circuit, error) {
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
		c.Inputs[i].StatePathElements = make([]frontend.Variable, protocol.StateTreeHeight)
		c.Inputs[i].NullifierLowPathElements = make([]frontend.Variable, protocol.NullifierTreeHeight)
	}
	return c, nil
}

func MustNewCircuit(shape protocol.Shape) *Circuit {
	circuit, err := NewCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

func MustNewSolanaCircuit(shape protocol.Shape) *Circuit {
	circuit, err := NewSolanaCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

func (c *Circuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

	nullifierPkFromSecret := NullifierPkCircuit(api, c.NullifierSecret)
	env := spendEnv{
		nullifierPkFromSecret: nullifierPkFromSecret,
		nullifierSecret:       c.NullifierSecret,
		requiresP256:          c.RequiresP256,
	}
	if c.RequiresP256 {
		p256OwnerKeyHash, err := P256OwnerKeyHashFromPubkeyCircuit(api, c.P256Pub)
		if err != nil {
			return err
		}
		p256Message, err := p256MessageHashToP256Fr(api, c.P256MessageHash)
		if err != nil {
			return err
		}
		env.p256OwnerKeyHash = p256OwnerKeyHash
		env.p256SigValid = c.P256Pub.IsValid(
			api,
			sw_emulated.GetCurveParams[emulated.P256Fp](),
			p256Message,
			&c.P256Sig,
		)
	} else {
		// Solana-only rail: no P256 gadget. p256OwnerKeyHash is never selected
		// (constrainInput forces every real input to be Solana-owned), and there
		// is no P256 signature, so pin the message hash to 0. p256SigValid is
		// unused (set to a constant for the gated checks that are never active).
		api.AssertIsEqual(c.P256MessageHash, 0)
		env.p256OwnerKeyHash = frontend.Variable(0)
		env.p256SigValid = frontend.Variable(1)
	}
	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i := 0; i < c.Shape.NInputs; i++ {
		inputHashes[i] = constrainInput(api, c.Inputs[i], env)
	}
	c.assertDistinctNullifiers(api)
	c.assertSingleOwner(api)

	outputHashes := make([]frontend.Variable, c.Shape.NOutputs)
	for i := 0; i < c.Shape.NOutputs; i++ {
		outputHashes[i] = constrainOutput(api, c.Outputs[i])
	}

	assertBalanceConservation(
		api,
		c.inputUtxos(),
		c.outputUtxos(),
		c.PublicSolAmount,
		c.PublicSplAmount,
		c.PublicSplAssetPubkey,
	)

	// Default transact carries no program/zone authorization: the tx-level
	// program/policy fields must be zero (SPP also reconstructs them as zero
	// on-chain). Zone flows would set these via zone_transact.
	api.AssertIsEqual(c.ProgramIDHashchain, 0)
	api.AssertIsEqual(c.DataHash, 0)
	api.AssertIsEqual(c.ZoneDataHash, 0)

	privateTxHash := PrivateTxHashCircuit(
		api,
		inputHashes,
		outputHashes,
		c.ExternalDataHash,
		c.ExpiryUnixTs,
	)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	api.AssertIsEqual(c.PublicInputHash, c.publicInputHash(api))
	return nil
}

func (c *Circuit) publicInputHash(api frontend.API) frontend.Variable {
	return gadget.HashChain(api, []frontend.Variable{
		gadget.HashChain(api, c.inputNullifiers()),
		gadget.HashChain(api, c.outputHashes()),
		gadget.HashChain(api, c.inputUtxoRoots()),
		gadget.HashChain(api, c.inputNullifierRoots()),
		c.PrivateTxHash,
		c.P256MessageHash,
		c.ExternalDataHash,
		c.PublicSolAmount,
		c.PublicSplAmount,
		c.PublicSplAssetPubkey,
		c.ProgramIDHashchain,
		c.SolanaPubkeyHash,
		c.DataHash,
		c.ZoneDataHash,
		gadget.HashChain(api, c.inputSolanaPkHashes()),
	})
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

func (c *Circuit) inputNullifiers() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].Nullifier
	}
	return out
}

func (c *Circuit) outputHashes() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Outputs))
	for i := range c.Outputs {
		out[i] = c.Outputs[i].Hash
	}
	return out
}

func (c *Circuit) inputUtxoRoots() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].UtxoTreeRoot
	}
	return out
}

func (c *Circuit) inputNullifierRoots() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].NullifierRoot
	}
	return out
}

func (c *Circuit) inputSolanaPkHashes() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].SolanaPkHash
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
		heights := []struct {
			name string
			got  int
			want int
		}{
			{"state path elements", len(input.StatePathElements), protocol.StateTreeHeight},
			{"nullifier low path elements", len(input.NullifierLowPathElements), protocol.NullifierTreeHeight},
		}
		for _, h := range heights {
			if h.got != h.want {
				return fmt.Errorf("spp: %s %d height mismatch: got %d want %d", h.name, i, h.got, h.want)
			}
		}
	}
	return nil
}
