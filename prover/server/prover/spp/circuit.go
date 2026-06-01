package spp

import (
	"fmt"

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

// Input is one spent UTXO plus the witnesses that authorize the spend: the
// owner material, a proof that the UTXO is in the state tree, and a proof that
// its nullifier is not yet in the nullifier tree.
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
	NullifierSecret  frontend.Variable
	P256Pub          gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	P256Sig          gnarkecdsa.Signature[emulated.P256Fr]

	// Logical public inputs. They are folded into PublicInputHash so the
	// on-chain verifier can rebuild one BN254 field element from instruction
	// data and account state.
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

	env := spendEnv{
		nullifierPkFromSecret: nullifierPkFromSecret,
		p256OwnerKeyHash:      p256OwnerKeyHash,
		p256SigValid:          p256SigValid,
		nullifierSecret:       c.NullifierSecret,
	}
	inputHashes := make([]frontend.Variable, len(c.Inputs))
	for i := range c.Inputs {
		inputHashes[i] = constrainInput(api, c.Inputs[i], env)
	}
	c.assertDistinctNullifiers(api)

	outputHashes := make([]frontend.Variable, len(c.Outputs))
	for i := range c.Outputs {
		outputHashes[i] = constrainOutput(api, c.Outputs[i])
	}

	assertBalanceConservation(
		api,
		c.Inputs,
		c.Outputs,
		c.PublicSolAmount,
		c.PublicSplAmount,
		c.PublicSplAssetPubkey,
	)

	privateTxHash := PrivateTxHashCircuit(api, inputHashes, outputHashes, c.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	api.AssertIsEqual(c.PublicInputHash, c.publicInputHash(api))
	return nil
}

// publicInputHash folds the logical public inputs in-circuit. The order must
// match the off-circuit PublicInputHash (and LogicalPublicInputNames), or the
// on-chain verifier would compute a different value. Keep the two in sync.
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
