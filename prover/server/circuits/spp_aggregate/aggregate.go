// Package spp_aggregate holds the outer circuit that verifies a batch of SPP
// transaction proofs and exposes one hash over their public inputs.
//
// Every inner verifying key is a compile-time constant, not a witness, so the
// outer verifying key alone names which inner circuits a batch proved, slot by
// slot. The on-chain selector binds a batch to its slot list through that.
//
// Recursion is BN254 in BN254, so the inner scalar field is emulated in the
// outer field. The on-chain verifier is BN254, so no cheaper curve pair is
// available.
package spp_aggregate

import (
	"fmt"

	"zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/commitments/pedersen"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// Every batchable circuit exposes one public input, the Poseidon hash the
// program recomputes.
const innerPublicInputs = 1

type (
	InnerProof        = stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	InnerWitness      = stdgroth16.Witness[sw_bn254.ScalarField]
	InnerVerifyingKey = stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
)

// Circuit proves that every element of Proofs verifies against its slot's
// verifying key and that AggregateInputHash chains their public inputs in
// order.
type Circuit struct {
	// Poseidon chain over the inner public input hashes, in slot order. The
	// only public input, which keeps the on-chain key the shape the shielded
	// pool already verifies.
	AggregateInputHash frontend.Variable `gnark:",public"`

	Proofs    []InnerProof
	Witnesses []InnerWitness

	// One key per slot, excluded from the witness. A key supplied at proving
	// time would let a batch choose which circuit a slot verified against.
	// Build each with stdgroth16.ValueOfVerifyingKeyFixed, which
	// WithFixedVerifyingKey requires.
	VerifyingKeys []InnerVerifyingKey `gnark:"-"`
}

// NewCircuit returns the compile-time skeleton for a batch with one key per
// slot. A uniform batch repeats one key. The proof and witness placeholders
// follow each key's commitment count, and every slot exposes exactly one
// public input.
func NewCircuit(vks []InnerVerifyingKey) (*Circuit, error) {
	if len(vks) < 2 {
		return nil, fmt.Errorf("batch size %d does not amortize a verification", len(vks))
	}
	c := &Circuit{
		Proofs:        make([]InnerProof, len(vks)),
		Witnesses:     make([]InnerWitness, len(vks)),
		VerifyingKeys: vks,
	}
	for i, vk := range vks {
		commitments := len(vk.CommitmentKeys)
		if want := innerPublicInputs + 1 + commitments; len(vk.G1.K) != want {
			return nil, fmt.Errorf(
				"slot %d key has %d IC points against %d commitments, want %d",
				i, len(vk.G1.K), commitments, want,
			)
		}
		c.Proofs[i] = InnerProof{
			Commitments: make([]pedersen.Commitment[sw_bn254.G1Affine], commitments),
		}
		c.Witnesses[i] = InnerWitness{
			Public: make([]emulated.Element[sw_bn254.ScalarField], innerPublicInputs),
		}
	}
	return c, nil
}

func (c *Circuit) Define(api frontend.API) error {
	if len(c.Proofs) != len(c.Witnesses) || len(c.Proofs) != len(c.VerifyingKeys) {
		return fmt.Errorf(
			"%d proofs against %d witnesses and %d keys",
			len(c.Proofs), len(c.Witnesses), len(c.VerifyingKeys),
		)
	}
	if len(c.Proofs) == 0 {
		return fmt.Errorf("empty batch")
	}

	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}

	hashes := make([]frontend.Variable, len(c.Proofs))
	for i := range c.Proofs {
		// The batched proofs are the bytes the shielded pool verifies on chain,
		// so their BSB22 challenge follows the native RFC 9380 derivation.
		// Without this option the P256 rail fails here.
		if err := verifier.AssertProof(
			c.VerifyingKeys[i], c.Proofs[i], c.Witnesses[i],
			stdgroth16.WithNativeHashToField(), stdgroth16.WithFixedVerifyingKey(),
		); err != nil {
			return fmt.Errorf("proof %d: %w", i, err)
		}
		if hashes[i], err = publicInputHash(api, field, c.Witnesses[i]); err != nil {
			return fmt.Errorf("proof %d: %w", i, err)
		}
	}

	// Poseidon left fold, matching create_hash_chain_from_slice in the shielded
	// pool. The fold is order sensitive, so batch order is part of the
	// statement, and with per-slot keys so is which kind fills which slot.
	api.AssertIsEqual(c.AggregateInputHash, gadget.HashChain(api, hashes))
	return nil
}

// publicInputHash reads the single public input of a batched proof as a native
// variable. A batch chains these opaque, so it never opens the preimage.
func publicInputHash(api frontend.API, field *emulated.Field[sw_bn254.ScalarField], w InnerWitness) (frontend.Variable, error) {
	if len(w.Public) != innerPublicInputs {
		return nil, fmt.Errorf("%d public inputs, want %d", len(w.Public), innerPublicInputs)
	}
	return gadget.OpenEmulatedInput(api, field, &w.Public[0]), nil
}
