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
// and is a thin wrapper around Transaction, the part every variant proves.
//
// A variant's Define runs:
//
//  1. view its witness as a Transaction    (per-variant transaction method)
//  2. validate the layout                  (Transaction.ValidateLayout plus the
//     variant's own slices)
//  3. assert its ring rule                 (ring.go) and its RingProgramID value
//  4. assert its published owner-tag rules (owner_tags.go)
//  5. resolve who signed into Signers      (signers.go; the P256 rails first
//     verify their one shared P256 signature)
//  6. Transaction.Constrain:
//     6.1. inputs (inputs.go): nullifier pubkeys, utxo hashes, owner binding,
//     nullifiers, inclusion, nullifier non-inclusion, uniqueness
//     6.2. outputs (outputs.go): dummy pinning, data authorization, hash binding
//     6.3. balance conservation            (balance.go)
//     6.4. private transaction hash        (private_tx_hash.go)
//     6.5. public input hash, ending in the variant's preimage tail

// Transaction is the transaction every variant proves, over one variant's
// already-allocated witness. It runs no signer, ring, or owner-tag check: the
// variant asserts those and resolves who signed, then hands the results to
// Constrain. What is left is shared by all five variants.
//
// It is deliberately not a gnark circuit struct: the witness schema stays the
// per-variant Public/Private structs, whose field paths are the keys the host
// mirrors.
type Transaction struct {
	Shape Shape

	Nullifiers         []frontend.Variable
	OutputHashes       []frontend.Variable
	UtxoTreeRoots      []frontend.Variable
	NullifierTreeRoots []frontend.Variable

	Inputs  []Input
	Outputs []UtxoCircuitFields
	// TxSecret is the transaction's single private random value. The output
	// blinding seed, each output blinding, and the private tx blinding derive
	// from it and the first nullifier (derivation.go).
	TxSecret frontend.Variable

	PrivateTxHash     frontend.Variable
	ExternalDataHash  frontend.Variable
	PublicAssets      [NPublicSlots]frontend.Variable
	PublicAmounts     [NPublicSlots]frontend.Variable
	RingProgramID     frontend.Variable
	SignerPkHashChain frontend.Variable
	AllowDummyInputs  frontend.Variable
	PublicInputHash   frontend.Variable

	// PreimageAfterPrivateTxHash contains variant-specific fields inserted
	// immediately after PrivateTxHash in the public-input-hash preimage.
	PreimageAfterPrivateTxHash []frontend.Variable

	// PreimageTail ends the public-input-hash preimage with everything that is
	// variant-dependent, in this order and count, mirroring the program's
	// recomputation (transact/verify.rs):
	//
	//	default ring:      output owner chain
	//	owner-signed ring: masked output owner chain
	//	ring authority:    owner tags stay private
	//
	// Constrain only chains these, never reads them: the count varies, so naming
	// them as fields would need nil-means-omit branching in here instead.
	PreimageTail []frontend.Variable
}

// LengthCheck is one witness slice length a variant adds to the core's.
type LengthCheck struct {
	Name string
	Got  int
	Want int
}

// ValidateLayout checks every slice the transaction indexes against the length
// the compiled skeleton was sized with, plus the variant's own slices. It must
// run before anything indexes them, so a variant calls it before asserting its
// ring rule or resolving its signers.
func (t Transaction) ValidateLayout(extra ...LengthCheck) error {
	if err := validateInputs(t.Shape.NInputs, t.Inputs); err != nil {
		return err
	}
	checks := []LengthCheck{
		{"nullifier", len(t.Nullifiers), t.Shape.NInputs},
		{"output hash", len(t.OutputHashes), t.Shape.NOutputs},
		{"utxo tree root", len(t.UtxoTreeRoots), t.Shape.NInputs},
		{"nullifier tree root", len(t.NullifierTreeRoots), t.Shape.NInputs},
		{"output", len(t.Outputs), t.Shape.NOutputs},
	}
	for _, check := range append(checks, extra...) {
		if err := ValidateLength(check.Name, check.Got, check.Want); err != nil {
			return err
		}
	}
	return nil
}

func (t Transaction) Constrain(api frontend.API, signers Signers, outputSigned []frontend.Variable) error {
	if err := ValidateLength("signer", len(signers), t.Shape.NInputs); err != nil {
		return err
	}
	if err := ValidateLength("output signed", len(outputSigned), t.Shape.NOutputs); err != nil {
		return err
	}
	api.AssertIsBoolean(t.AllowDummyInputs)
	// 1. check inputs
	inputHashes := make([]frontend.Variable, t.Shape.NInputs)
	addressHashes := make([]frontend.Variable, t.Shape.NInputs)
	for i, in := range t.Inputs {
		// AllowDummyInputs is SPP's nullifier-capacity gate: a spend consumes a
		// nullifier leaf for a UTXO leaf that already exists, while dummy and
		// address slots insert a nullifier without spending one. When the gate is
		// off, every input slot must therefore be a real spend, not just non-dummy.
		api.AssertIsEqual(
			api.Mul(api.Sub(1, t.AllowDummyInputs), api.Sub(1, in.isUtxo(api))),
			0,
		)
		signals := PublicInputUtxoInputs{
			Nullifier:         t.Nullifiers[i],
			UtxoTreeRoot:      t.UtxoTreeRoots[i],
			NullifierTreeRoot: t.NullifierTreeRoots[i],
			SignerPk:          signers[i],
		}
		inputHashes[i], addressHashes[i] = constrainInput(api, in, signals)
	}
	AssertDistinctNullifiers(api, t.Nullifiers)

	// 2. check outputs
	outputBlindingSeed := DeriveOutputBlindingSeed(api, t.Nullifiers[0], t.TxSecret)
	outputHashes := make([]frontend.Variable, t.Shape.NOutputs)
	for i, utxo := range t.Outputs {
		api.AssertIsEqual(
			utxo.Blinding,
			DeriveOutputBlinding(api, t.Nullifiers[0], outputBlindingSeed, i),
		)
		outputHashes[i] = ConstrainOutput(api, utxo, t.OutputHashes[i], outputSigned[i])
	}

	// 3. check balance
	assertBalanceConservation(
		api,
		inputUtxos(t.Inputs),
		t.Outputs,
		t.PublicAssets[:],
		t.PublicAmounts[:],
	)

	// 4. Check private tx hash.
	privateTxHash := PrivateTxHashCircuit(
		api,
		inputHashes,
		outputHashes,
		addressHashes,
		t.ExternalDataHash,
		DerivePrivateTxBlinding(api, t.Nullifiers[0], t.TxSecret),
	)
	api.AssertIsEqual(privateTxHash, t.PrivateTxHash)

	// 5. Check public input hash.
	api.AssertIsEqual(t.PublicInputHash, t.publicInputHash(api))
	return nil
}

func (t Transaction) publicInputHash(api frontend.API) frontend.Variable {
	fields := []frontend.Variable{
		gadget.HashChain(api, t.Nullifiers),
		gadget.HashChain(api, t.OutputHashes),
		gadget.HashChain(api, t.UtxoTreeRoots),
		gadget.HashChain(api, t.NullifierTreeRoots),
		t.PrivateTxHash,
	}
	fields = append(fields, t.PreimageAfterPrivateTxHash...)
	fields = append(fields, t.ExternalDataHash)
	fields = append(fields, publicSlots(t.PublicAssets, t.PublicAmounts)...)
	fields = append(fields, t.RingProgramID, t.SignerPkHashChain, t.AllowDummyInputs)
	fields = append(fields, t.PreimageTail...)
	return gadget.HashChain(api, fields)
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

// publicSlots returns the public movement slots interleaved as
// [asset_0, amount_0, asset_1, amount_1, asset_2, amount_2] — the canonical
// public-input-hash preimage order every variant and host mirror must share.
func publicSlots(assets, amounts [NPublicSlots]frontend.Variable) []frontend.Variable {
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
	// NPublicSlots is the number of distinct public assets whose aggregate
	// movement can be proven in one transaction.
	NPublicSlots = 3
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
