package shared

import (
	"fmt"

	"zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// This package holds the witness building blocks and constraint helpers shared
// by the SPP transaction circuit variants. Each variant (in the default/ and
// custom/ packages) owns its full witness layout as Public/Private sub-structs
// and defines the proof in this order:
//
//  1. validate layout                          (per-variant validateLayout)
//  2. build the signer array                   (signers.go; the P256 rails first
//     verify their shared P256 signature)
//  3. inputs (inputs.go):
//     3.1. create nullifier pubkeys
//     3.2. create utxo hashes
//     3.3. verify owner binding
//     3.4. create nullifiers
//     3.5. verify inclusion proof
//     3.6. verify nullifier non-inclusion proof
//     3.7. verify every nullifier is unique
//  4. outputs: bind output utxo hashes         (outputs.go)
//  5. verify balance conservation              (balance.go)
//  6. check private transaction hash           (private_tx_hash.go)
//  7. check public inputs hash                 (per-variant public input hash)

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

// PublicSlots returns the public movement slots interleaved as
// [asset_0, amount_0, asset_1, amount_1] — the canonical public-input-hash
// preimage order every variant and host mirror must share.
func PublicSlots(assets, amounts [NPublicSlots]frontend.Variable) []frontend.Variable {
	slots := make([]frontend.Variable, 0, 2*NPublicSlots)
	for i := 0; i < NPublicSlots; i++ {
		slots = append(slots, assets[i], amounts[i])
	}
	return slots
}

// ValidateLength checks one witness slice against the length the compiled
// skeleton was sized with.
func ValidateLength(name string, got, want int) error {
	if got != want {
		return fmt.Errorf("spp: %s count mismatch: got %d want %d", name, got, want)
	}
	return nil
}

// These mirror the SPP protocol constants, kept in the circuits package so it
// depends on no host code (see circuits/CLAUDE.md). They must stay in sync with
// prover/spp/protocol.
const (
	// NPublicSlots is the number of public (asset, amount) movement slots in
	// every transaction circuit. Host convention: slot 0 is the SOL leg, slot 1
	// the SPL leg.
	NPublicSlots = 2
	// DummyDomain is the domain tag for dummy (padding) utxos.
	DummyDomain = 1
	// AddressDomain is the domain tag for address utxos, separating address
	// hashes and nullifiers from spendable ones.
	AddressDomain = 2
	// UtxoDomain is the domain tag folded into every spendable UTXO commitment.
	UtxoDomain = 3
	// StateTreeHeight is the SPP state (UTXO) merkle tree height.
	StateTreeHeight = 32
	// NullifierTreeHeight is the SPP nullifier tree height.
	NullifierTreeHeight = 40
)

// assertZeroWhen constrains v == 0 only when cond == 1 (see gadget.AssertZeroWhen).
func assertZeroWhen(api frontend.API, cond, v frontend.Variable) {
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: cond, V: v})
}

// AssertWhen constrains check == 1 only when cond == 1. Check functions return
// an ungated satisfied bit; the kind gate is applied only at the call site.
func AssertWhen(api frontend.API, cond, check frontend.Variable) {
	assertZeroWhen(api, cond, api.Sub(1, check))
}
