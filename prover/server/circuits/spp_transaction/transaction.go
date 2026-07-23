package transaction

import (
	"fmt"
	"math/big"

	"zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// Circuit is the shared witness layout of every SPP transaction circuit
// variant. It carries no constraints itself; each variant embeds it and defines
// the proof in the order below (each step lives in the named file):
//
//  1. validate layout                          (transaction.go)
//  2. build the spend env                      (p256 rail: circuit_default_zone_p256.go,
//     eddsa rail: circuit_default_zone_eddsa_only.go)
//  3. inputs (inputs.go):
//     3.1. create nullifier pubkeys
//     3.2. create utxo hashes
//     3.3. verify owner binding
//     3.4. create nullifiers
//     3.5. verify inclusion proof
//     3.6. verify nullifier non-inclusion proof
//     3.7. verify every nullifier is unique
//  4. outputs: create output utxo hashes       (outputs.go)
//  5. verify balance conservation              (balance.go)
//  6. check private transaction hash           (private_tx_hash.go)
//  7. check public inputs hash                 (per-variant public input hash)
type Circuit struct {
	Shape Shape `gnark:"-"`

	Inputs  []Input
	Outputs []Output

	ExternalDataHash frontend.Variable
	P256Pub          P256PublicKey
	P256Sig          P256Signature
	// P256SigningPkField is the shared P256 signing key's pk_field; public in the
	// default-zone variants so SPP fills the P256-owned input owner entries.
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

func newCircuit(shape Shape) (*Circuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	c := &Circuit{
		Shape:   shape,
		Inputs:  make([]Input, shape.NInputs),
		Outputs: make([]Output, shape.NOutputs),
	}
	for i := 0; i < shape.NInputs; i++ {
		c.Inputs[i].StatePathElements = make([]frontend.Variable, StateTreeHeight)
		c.Inputs[i].NullifierLowPathElements = make([]frontend.Variable, NullifierTreeHeight)
	}
	return c, nil
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
	// UtxoDomain is the domain tag folded into every spendable UTXO commitment.
	UtxoDomain = 1
	// AddressDomain is the domain tag for address utxos, separating address
	// hashes and nullifiers from spendable ones.
	AddressDomain = 2
	// DummyDomain is the domain tag for dummy (padding) utxos.
	DummyDomain = 3
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

// assertWhen constrains check == 1 only when cond == 1. Check functions return
// an ungated satisfied bit; the kind gate is applied only at the call site.
func assertWhen(api frontend.API, cond, check frontend.Variable) {
	assertZeroWhen(api, cond, api.Sub(1, check))
}
