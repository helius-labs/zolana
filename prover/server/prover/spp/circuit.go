package spp

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

// MerkleProof is a sibling path and the per-level direction bits for a
// fixed-height binary Merkle tree.
type MerkleProof struct {
	Siblings   []frontend.Variable
	Directions []frontend.Variable
}

func newMerkleProof(height int) MerkleProof {
	return MerkleProof{
		Siblings:   make([]frontend.Variable, height),
		Directions: make([]frontend.Variable, height),
	}
}

func (p MerkleProof) validate(height int) error {
	if len(p.Siblings) != height || len(p.Directions) != height {
		return fmt.Errorf("path length mismatch: siblings=%d directions=%d want=%d",
			len(p.Siblings), len(p.Directions), height)
	}
	return nil
}

// Input is one spent UTXO together with the witnesses that authorize the spend:
// the owner material, its inclusion in the state tree, and the non-inclusion of
// its nullifier in the indexed nullifier tree.
type Input struct {
	Utxo         UtxoCircuitFields
	IsDummy      frontend.Variable
	NullifierPk  frontend.Variable
	SolanaPkHash frontend.Variable

	// Folded into PublicInputHash.
	Nullifier     frontend.Variable
	UtxoTreeRoot  frontend.Variable
	NullifierRoot frontend.Variable

	// Inclusion of Utxo in the state tree.
	State MerkleProof

	// Non-inclusion of Nullifier in the indexed nullifier tree: the adjacent
	// low leaf (NfLowValue, NfNextValue) and its path to NullifierRoot.
	NfLowValue  frontend.Variable
	NfNextValue frontend.Variable
	NfLow       MerkleProof
}

// Output is one created UTXO with its dummy flag and committed hash.
type Output struct {
	Utxo    UtxoCircuitFields
	IsDummy frontend.Variable
	Hash    frontend.Variable // folded into PublicInputHash
}

// Circuit is the SPP circuit for one fixed (N inputs, M outputs) shape.
type Circuit struct {
	Shape Shape `gnark:"-"`

	Inputs  []Input
	Outputs []Output

	ExternalDataHash frontend.Variable
	ExpiryUnixTs     frontend.Variable
	NullifierSecret  frontend.Variable
	P256Pub          gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	P256Sig          gnarkecdsa.Signature[emulated.P256Fr]

	// Logical public inputs, folded into PublicInputHash so the on-chain
	// verifier can reconstruct one BN254 field element from instruction data
	// and account state.
	PrivateTxHash        frontend.Variable
	PublicSolAmount      frontend.Variable
	PublicSplAmount      frontend.Variable
	PublicSplAssetPubkey frontend.Variable
	ProgramIDHashChain   frontend.Variable
	SolanaPubkeyHash     frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

func NewCircuit(shape Shape) (*Circuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	c := &Circuit{
		Shape:   shape,
		Inputs:  make([]Input, shape.NInputs),
		Outputs: make([]Output, shape.NOutputs),
	}
	for i := range c.Inputs {
		c.Inputs[i].State = newMerkleProof(StateTreeHeight)
		c.Inputs[i].NfLow = newMerkleProof(NullifierTreeHeight)
	}
	return c, nil
}

func MustNewCircuit(shape Shape) *Circuit {
	circuit, err := NewCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

// assertEqualWhen constrains a == b only when cond == 1 (cond must be boolean).
func assertEqualWhen(api frontend.API, cond, a, b frontend.Variable) {
	api.AssertIsEqual(api.Mul(cond, api.Sub(a, b)), 0)
}

// assertZeroWhen constrains v == 0 only when cond == 1 (cond must be boolean).
func assertZeroWhen(api frontend.API, cond, v frontend.Variable) {
	api.AssertIsEqual(api.Mul(cond, v), 0)
}

func (c *Circuit) Define(api frontend.API) error {
	if err := c.validateShape(); err != nil {
		return err
	}

	nullifierPkFromSecret := NullifierPkCircuit(api, c.NullifierSecret)
	p256OwnerKeyHash, err := P256OwnerKeyHashFromPubkeyCircuit(api, c.P256Pub)
	if err != nil {
		return err
	}
	p256Message, err := privateTxHashToP256Fr(api, c.PrivateTxHash)
	if err != nil {
		return err
	}
	p256SigValid := c.P256Pub.IsValid(
		api,
		sw_emulated.GetCurveParams[emulated.P256Fp](),
		p256Message,
		&c.P256Sig,
	)

	inputHashes := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		in := c.Inputs[i]
		api.AssertIsBoolean(in.IsDummy)
		notDummy := api.Sub(1, in.IsDummy)

		assertZeroWhen(api, in.IsDummy, in.Utxo.AssetAmount)
		assertEqualWhen(api, notDummy, in.Utxo.Domain, UtxoDomain) // pin domain (audit #2)

		utxoHash := UtxoHashCircuit(api, in.Utxo)
		inputHashes[i] = api.Select(in.IsDummy, frontend.Variable(0), utxoHash)

		// Inclusion: utxoHash is a leaf of the state tree at UtxoTreeRoot.
		stateRoot := StatePathFoldCircuit(api, utxoHash, in.State.Siblings, in.State.Directions)
		assertEqualWhen(api, notDummy, stateRoot, in.UtxoTreeRoot)

		// Owner binding: P256 inputs (SolanaPkHash == 0) recompute the owner key
		// hash from the witnessed P256 point; Solana inputs use the public hash.
		isP256 := api.IsZero(in.SolanaPkHash)
		ownerKeyHash := api.Select(isP256, p256OwnerKeyHash, in.SolanaPkHash)
		ownerHash := OwnerHashCircuit(api, ownerKeyHash, in.NullifierPk)
		assertEqualWhen(api, notDummy, ownerHash, in.Utxo.Owner)
		assertEqualWhen(api, notDummy, nullifierPkFromSecret, in.NullifierPk)
		// P256 inputs must carry a valid signature; Solana inputs are verified
		// by SPP out of circuit.
		api.AssertIsEqual(api.Mul(notDummy, isP256, api.Sub(1, p256SigValid)), 0)
		assertZeroWhen(api, in.IsDummy, in.NullifierPk)
		assertZeroWhen(api, in.IsDummy, in.SolanaPkHash)

		nullifier := NullifierHashCircuit(api, utxoHash, in.Utxo.Blinding, c.NullifierSecret)
		assertEqualWhen(api, notDummy, nullifier, in.Nullifier)
		assertZeroWhen(api, in.IsDummy, in.Nullifier)

		// Non-inclusion: the low leaf is in the nullifier tree and brackets the
		// nullifier (NfLowValue < Nullifier < NfNextValue).
		lowLeaf := IndexedLeafHashCircuit(api, in.NfLowValue, in.NfNextValue)
		nfRoot := StatePathFoldCircuit(api, lowLeaf, in.NfLow.Siblings, in.NfLow.Directions)
		assertEqualWhen(api, notDummy, nfRoot, in.NullifierRoot)

		// Strict ordering low < nullifier < next, expressed with
		// AssertIsLessOrEqual + AssertIsDifferent (no `+1`, which could wrap at
		// the field boundary). Dummy inputs use 0 < 1 < 2. Audit findings #4/#5.
		low := api.Select(in.IsDummy, frontend.Variable(0), in.NfLowValue)
		nf := api.Select(in.IsDummy, frontend.Variable(1), in.Nullifier)
		next := api.Select(in.IsDummy, frontend.Variable(2), in.NfNextValue)
		api.AssertIsLessOrEqual(low, nf)
		api.AssertIsDifferent(low, nf)
		api.AssertIsLessOrEqual(nf, next)
		api.AssertIsDifferent(nf, next)
	}

	// Reject re-spending the same input twice in one transaction: every pair of
	// real inputs must carry distinct nullifiers (audit #1). Dummy inputs all
	// carry nullifier 0 and are excluded.
	for i := range c.Inputs {
		for j := i + 1; j < len(c.Inputs); j++ {
			bothReal := api.Mul(api.Sub(1, c.Inputs[i].IsDummy), api.Sub(1, c.Inputs[j].IsDummy))
			sameNullifier := api.IsZero(api.Sub(c.Inputs[i].Nullifier, c.Inputs[j].Nullifier))
			api.AssertIsEqual(api.Mul(bothReal, sameNullifier), 0)
		}
	}

	outputHashes := make([]frontend.Variable, len(c.Outputs))
	for i := range c.Outputs {
		out := c.Outputs[i]
		api.AssertIsBoolean(out.IsDummy)
		notDummy := api.Sub(1, out.IsDummy)

		assertZeroWhen(api, out.IsDummy, out.Utxo.AssetAmount)
		assertEqualWhen(api, notDummy, out.Utxo.Domain, UtxoDomain) // pin domain (audit #2)

		utxoHash := UtxoHashCircuit(api, out.Utxo)
		outputHashes[i] = api.Select(out.IsDummy, frontend.Variable(0), utxoHash)
		assertEqualWhen(api, notDummy, utxoHash, out.Hash)
		assertZeroWhen(api, out.IsDummy, out.Hash)
	}

	assertBalanceConservation(
		api,
		c.inputUtxos(),
		c.outputUtxos(),
		c.PublicSolAmount,
		c.PublicSplAmount,
		c.PublicSplAssetPubkey,
	)

	privateTxHash := PrivateTxHashCircuit(api, inputHashes, outputHashes, c.ExternalDataHash, c.ExpiryUnixTs)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	api.AssertIsEqual(c.PublicInputHash, c.publicInputHash(api))
	return nil
}

func (c *Circuit) inputUtxos() []UtxoCircuitFields {
	utxos := make([]UtxoCircuitFields, len(c.Inputs))
	for i := range c.Inputs {
		utxos[i] = c.Inputs[i].Utxo
	}
	return utxos
}

func (c *Circuit) outputUtxos() []UtxoCircuitFields {
	utxos := make([]UtxoCircuitFields, len(c.Outputs))
	for i := range c.Outputs {
		utxos[i] = c.Outputs[i].Utxo
	}
	return utxos
}

func (c *Circuit) publicInputHash(api frontend.API) frontend.Variable {
	nullifiers := make([]frontend.Variable, len(c.Inputs))
	utxoRoots := make([]frontend.Variable, len(c.Inputs))
	nullifierRoots := make([]frontend.Variable, len(c.Inputs))
	solanaPkHashes := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		nullifiers[i] = c.Inputs[i].Nullifier
		utxoRoots[i] = c.Inputs[i].UtxoTreeRoot
		nullifierRoots[i] = c.Inputs[i].NullifierRoot
		solanaPkHashes[i] = c.Inputs[i].SolanaPkHash
	}
	outputHashes := make([]frontend.Variable, len(c.Outputs))
	for i := range c.Outputs {
		outputHashes[i] = c.Outputs[i].Hash
	}

	return HashChainCircuit(api, []frontend.Variable{
		HashChainCircuit(api, nullifiers),
		HashChainCircuit(api, outputHashes),
		HashChainCircuit(api, utxoRoots),
		HashChainCircuit(api, nullifierRoots),
		c.PrivateTxHash,
		c.ExternalDataHash,
		c.PublicSolAmount,
		c.PublicSplAmount,
		c.PublicSplAssetPubkey,
		c.ProgramIDHashChain,
		c.SolanaPubkeyHash,
		HashChainCircuit(api, solanaPkHashes),
	})
}

func (c *Circuit) validateShape() error {
	if err := c.Shape.Validate(); err != nil {
		return err
	}
	if len(c.Inputs) != c.Shape.NInputs {
		return fmt.Errorf("spp: input count mismatch: got %d want %d", len(c.Inputs), c.Shape.NInputs)
	}
	if len(c.Outputs) != c.Shape.NOutputs {
		return fmt.Errorf("spp: output count mismatch: got %d want %d", len(c.Outputs), c.Shape.NOutputs)
	}
	for i := range c.Inputs {
		if err := c.Inputs[i].State.validate(StateTreeHeight); err != nil {
			return fmt.Errorf("spp: input %d state proof: %w", i, err)
		}
		if err := c.Inputs[i].NfLow.validate(NullifierTreeHeight); err != nil {
			return fmt.Errorf("spp: input %d nullifier proof: %w", i, err)
		}
	}
	return nil
}

type PublicInputs struct {
	Nullifiers           []*big.Int
	OutputUtxoHashes     []*big.Int
	UtxoTreeRoots        []*big.Int
	NullifierRoots       []*big.Int
	PrivateTxHash        *big.Int
	ExternalDataHash     *big.Int
	ExpiryUnixTs         *big.Int
	PublicSolAmount      *big.Int
	PublicSplAmount      *big.Int
	PublicSplAssetPubkey *big.Int
	ProgramIDHashChain   *big.Int
	SolanaPubkeyHash     *big.Int
	SolanaPkHashes       []*big.Int
}

func PublicInputHash(inputs PublicInputs) (*big.Int, error) {
	nullifierChain, err := HashChain(inputs.Nullifiers)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash nullifier chain: %w", err)
	}
	outputChain, err := HashChain(inputs.OutputUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash output chain: %w", err)
	}
	utxoRootChain, err := HashChain(inputs.UtxoTreeRoots)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash UTXO root chain: %w", err)
	}
	nullifierRootChain, err := HashChain(inputs.NullifierRoots)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash nullifier root chain: %w", err)
	}
	solanaOwnerKeyHashChain, err := HashChain(inputs.SolanaPkHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash solana pk hash chain: %w", err)
	}
	return HashChain([]*big.Int{
		nullifierChain,
		outputChain,
		utxoRootChain,
		nullifierRootChain,
		inputs.PrivateTxHash,
		inputs.ExternalDataHash,
		inputs.PublicSolAmount,
		inputs.PublicSplAmount,
		inputs.PublicSplAssetPubkey,
		inputs.ProgramIDHashChain,
		inputs.SolanaPubkeyHash,
		solanaOwnerKeyHashChain,
	})
}
