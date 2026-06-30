package transaction

import (
	"fmt"
	"math/big"

	"zolana/prover/circuits/gadget"

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
	// Solana-owned.
	RequiresP256  bool `gnark:"-"`
	Confidential  bool `gnark:"-"`
	ZoneAuthority bool `gnark:"-"`

	Inputs  []Input
	Outputs []Output

	ExternalDataHash frontend.Variable
	P256Pub          P256PublicKey
	P256Sig          P256Signature
	// P256SigningPkField is the shared P256 signing key's pk_field; public in the
	// confidential variant so SPP fills the P256-owned input owner entries.
	P256SigningPkField frontend.Variable

	PrivateTxHash frontend.Variable
	// P256 ECDSA message digest (full SHA-256) carried as two big-endian 128-bit
	// limbs: a 256-bit value does not fit in one BN254 element. Both are 0 on the
	// Solana-only rail.
	P256MessageHashLow   frontend.Variable
	P256MessageHashHigh  frontend.Variable
	PublicSolAmount      frontend.Variable
	PublicSplAmount      frontend.Variable
	PublicSplAssetPubkey frontend.Variable
	ZoneProgramID        frontend.Variable
	PayerPubkeyHash      frontend.Variable

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

	OwnerPkHash     frontend.Variable
	NullifierSecret frontend.Variable
}

type Output struct {
	Utxo    UtxoCircuitFields
	IsDummy frontend.Variable
	Hash    frontend.Variable

	// Confidential variant only: OwnerPkHash is the public owner tag, NullifierPk
	// the witnessed nullifier pubkey; together they recompute Utxo.Owner.
	OwnerPkHash frontend.Variable
	NullifierPk frontend.Variable
}

func NewTransferP256ConfidentialCircuit(shape Shape) (*Circuit, error) {
	return newCircuit(shape, true, true)
}

func NewTransferConfidentialCircuit(shape Shape) (*Circuit, error) {
	return newCircuit(shape, false, true)
}

func NewTransferP256ZoneCircuit(shape Shape) (*Circuit, error) {
	return newCircuit(shape, true, false)
}

func NewTransferZoneCircuit(shape Shape) (*Circuit, error) {
	return newCircuit(shape, false, false)
}

func NewTransferZoneAuthorityCircuit(shape Shape) (*Circuit, error) {
	c, err := newCircuit(shape, false, false)
	if err != nil {
		return nil, err
	}
	c.ZoneAuthority = true
	return c, nil
}

func newCircuit(shape Shape, requiresP256, confidential bool) (*Circuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	c := &Circuit{
		Shape:        shape,
		RequiresP256: requiresP256,
		Confidential: confidential,
		Inputs:       make([]Input, shape.NInputs),
		Outputs:      make([]Output, shape.NOutputs),
	}
	for i := 0; i < shape.NInputs; i++ {
		c.Inputs[i].StatePathElements = make([]frontend.Variable, StateTreeHeight)
		c.Inputs[i].NullifierLowPathElements = make([]frontend.Variable, NullifierTreeHeight)
	}
	return c, nil
}

// Define runs the proof in the order below; each step lives in the named file.
//
//  1. validate layout                          (circuit.go)
//  2. create nullifier pubkeys                 (inputs.go)
//  3. verify p256 signature                    (p256.go)
//  4. inputs (inputs.go):
//     4.1. create utxo hashes
//     4.2. verify owner binding
//     4.3. create nullifiers
//     4.4. verify inclusion proof
//     4.5. verify nullifier non-inclusion proof
//     4.6. verify every nullifier is unique
//  5. outputs: create output utxo hashes       (outputs.go)
//  6. verify balance conservation              (balance.go)
//  7. check private transaction hash           (private_tx_hash.go)
//  8. check public inputs hash                 (circuit.go)
func (c *Circuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

	zone := !c.Confidential

	// Ownership
	env := spendEnv{
		requiresP256:       c.RequiresP256,
		confidential:       c.Confidential,
		zone:               zone,
		zoneAuthority:      c.ZoneAuthority,
		zoneProgramID:      c.ZoneProgramID,
		p256SigningPkField: c.P256SigningPkField,
	}
	if c.RequiresP256 {
		ownerKeyHash, err := OwnerPkFieldFromPubkeyCircuit(api, c.P256Pub)
		if err != nil {
			return err
		}
		p256Message, err := p256MessageHashToP256Fr(api, c.P256MessageHashLow, c.P256MessageHashHigh)
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
		api.AssertIsEqual(c.P256MessageHashLow, 0)
		api.AssertIsEqual(c.P256MessageHashHigh, 0)
		env.p256PkField = frontend.Variable(0)
		env.p256SigValid = frontend.Variable(1)
	}
	// Confidential variant exposes the shared P256 signing key's pk_field so SPP
	// can reconstruct P256-owned input entries; pin it to the recomputed key
	// (0 on the Solana-only rail).
	if c.Confidential {
		api.AssertIsEqual(c.P256SigningPkField, env.p256PkField)
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
	addressHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i := 0; i < c.Shape.NInputs; i++ {
		inputHashes[i], addressHashes[i] = constrainInput(api, c.Inputs[i], nullifierPks[i], env)
	}
	c.assertDistinctNullifiers(api)
	// Outputs
	OutputHashes := make([]frontend.Variable, c.Shape.NOutputs)
	for i := 0; i < c.Shape.NOutputs; i++ {
		OutputHashes[i] = constrainOutput(api, c.Outputs[i], c.Confidential, zone, c.ZoneAuthority, c.ZoneProgramID)
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

	if !zone {
		api.AssertIsEqual(c.ZoneProgramID, 0)
	}
	if c.ZoneAuthority {
		api.AssertIsDifferent(c.ZoneProgramID, 0)
	}

	privateTxHash := PrivateTxHashCircuit(
		api,
		inputHashes,
		OutputHashes,
		addressHashes,
		c.ExternalDataHash,
	)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	api.AssertIsEqual(c.PublicInputHash, c.publicInputHash(api))
	return nil
}

func (c *Circuit) publicInputHash(api frontend.API) frontend.Variable {
	fields := []frontend.Variable{
		gadget.HashChain(api, c.InputNullifiers()),
		gadget.HashChain(api, c.OutputHashes()),
		gadget.HashChain(api, c.InputUtxoRoots()),
		gadget.HashChain(api, c.InputNullifierTreeRoots()),
		c.PrivateTxHash,
		gadget.PoseidonHash(api, []frontend.Variable{c.P256MessageHashLow, c.P256MessageHashHigh}),
		c.ExternalDataHash,
		c.PublicSolAmount,
		c.PublicSplAmount,
		c.PublicSplAssetPubkey,
		c.ZoneProgramID,
		c.PayerPubkeyHash,
	}
	if !c.ZoneAuthority {
		fields = append(fields, gadget.HashChain(api, c.InputOwnerPkHashes()))
	}
	if c.Confidential {
		fields = append(fields,
			gadget.HashChain(api, c.OutputOwnerPkHashes()),
			c.P256SigningPkField,
		)
	}
	return gadget.HashChain(api, fields)
}

func (c *Circuit) InputOwnerPkHashes() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		out[i] = c.Inputs[i].OwnerPkHash
	}
	return out
}

func (c *Circuit) OutputOwnerPkHashes() []frontend.Variable {
	out := make([]frontend.Variable, len(c.Outputs))
	for i := range c.Outputs {
		out[i] = c.Outputs[i].OwnerPkHash
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

// Shape identifies one fixed-size SPP transaction circuit by its input and
// output counts. The host mirrors this as protocol.Shape (with the supported-set
// metadata); the circuit only needs the counts and that they are positive.
type Shape struct {
	NInputs  int
	NOutputs int
}

// Validate checks the counts the circuit relies on to size its witness. The
// supported-shape check lives host-side (protocol.Shape.IsSupported).
func (s Shape) Validate() error {
	if s.NInputs < 1 {
		return fmt.Errorf("spp: NInputs must be >= 1, got %d", s.NInputs)
	}
	if s.NOutputs < 1 {
		return fmt.Errorf("spp: NOutputs must be >= 1, got %d", s.NOutputs)
	}
	return nil
}

// These mirror the SPP protocol constants, kept in the circuits package so it
// depends on no host code (see circuits/CLAUDE.md). They must stay in sync with
// prover/spp/protocol.
const (
	// UtxoDomain is the domain tag folded into every UTXO commitment.
	UtxoDomain = 1
	// StateTreeHeight is the SPP state (UTXO) merkle tree height.
	StateTreeHeight = 32
	// NullifierTreeHeight is the SPP nullifier tree height.
	NullifierTreeHeight = 40
)

// solAssetValue is the UTXO asset field for native SOL: Poseidon(0, 0), the
// all-zero address encoded as a SolanaPkField. Precomputed so the circuits
// package needs no host Poseidon; protocol.SolAsset() is the source of truth.
var solAssetValue, _ = new(big.Int).SetString(
	"14744269619966411208579211824598458697587494354926760081771325075741142829156", 10)

// SolAsset returns the native-SOL asset field used in UTXO commitments.
func SolAsset() *big.Int {
	return new(big.Int).Set(solAssetValue)
}

// assertEqualWhen constrains a == b only when cond == 1 (see
// gadget.AssertEqualWhen). For cond == 0 the check is vacuously satisfied.
func assertEqualWhen(api frontend.API, cond, a, b frontend.Variable) {
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: cond, A: a, B: b})
}

// assertZeroWhen constrains v == 0 only when cond == 1 (see gadget.AssertZeroWhen).
func assertZeroWhen(api frontend.API, cond, v frontend.Variable) {
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: cond, V: v})
}
