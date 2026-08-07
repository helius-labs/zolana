// Package squads_key_encryption_fold holds the outer circuit that folds several
// key-encryption legs into one proof over a wider recipient set.
//
// The key-encryption circuit is keyed by recipient count and only 1, 2, and 3
// have a key, while a ViewingKeyAccount holds more. Splitting the set across
// legs lifts that cap with one ceremony instead of one per count.
//
// The legs are not a sequence. They are parallel statements about one account,
// so the predicate between them is equality on everything the account holds
// once. Those fields are the prior state, the shared viewing key and its
// commitment, the shared ephemeral key, and the nullifier pair. Only the
// recipient triples differ.
//
// The fold's public input is the same chain a single circuit of the summed
// width would expose, so the program recomputes it exactly as it does today.
// Taking the shared fields from the first leg alone is sound only because of
// the equality assertions. Without them a later leg could encrypt a different
// secret and the chain would not show it.
//
// The inner verifying key is a compile-time constant, so the outer verifying
// key alone names the per-leg recipient count a fold proved.
package squads_key_encryption_fold

import (
	"fmt"

	"zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// The leg's public input is HashChain over a shared prefix, one triple per
// recipient key, then a shared suffix. These name the prefix positions.
const (
	oldStateHashIndex = iota
	sharedPkLoIndex
	sharedPkHiIndex
	commitmentIndex
	ephPkLoIndex
	ephPkHiIndex
	// PrefixLen is the count of leading fields every leg must agree on.
	PrefixLen
)

// KeyFields is the per-recipient triple of compressed key low, high, ciphertext
// hash.
const KeyFields = 3

// SuffixLen is the trailing nullifier pubkey and ciphertext hash, both shared.
const SuffixLen = 2

// PreimageLen is the leg public-input preimage length for keysPerLeg
// recipients.
func PreimageLen(keysPerLeg int) int {
	return PrefixLen + KeyFields*keysPerLeg + SuffixLen
}

type (
	InnerProof        = stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	InnerWitness      = stdgroth16.Witness[sw_bn254.ScalarField]
	InnerVerifyingKey = stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
)

// Circuit proves that every leg verifies, that the legs describe one account,
// and that FoldInputHash chains their union.
type Circuit struct {
	// The chain a single key-encryption circuit over every leg's recipients
	// would expose. The only public input, so the on-chain key keeps the shape
	// the zone already verifies.
	FoldInputHash frontend.Variable `gnark:",public"`

	Proofs    []InnerProof
	Witnesses []InnerWitness
	// Per leg, the key-encryption circuit's public-input preimage. Witnessed,
	// then bound to the proof's public input, so a leg cannot claim recipients
	// or an account state it did not prove.
	Preimages [][]frontend.Variable

	// Recipients per leg. It matches the inner key, so it is a constant.
	KeysPerLeg int `gnark:"-"`

	// Excluded from the witness. A key supplied at proving time would let a
	// fold choose which circuit it verified against.
	VerifyingKey InnerVerifyingKey `gnark:"-"`
}

// NewCircuit returns the compile-time skeleton for legs legs of keysPerLeg
// recipients each, against vk.
func NewCircuit(legs, keysPerLeg int, vk InnerVerifyingKey, innerCcs constraint.ConstraintSystem) (*Circuit, error) {
	if legs < 2 {
		return nil, fmt.Errorf("%d legs do not amortize a verification", legs)
	}
	if keysPerLeg < 1 {
		return nil, fmt.Errorf("%d keys per leg", keysPerLeg)
	}
	c := &Circuit{
		Proofs:       make([]InnerProof, legs),
		Witnesses:    make([]InnerWitness, legs),
		Preimages:    make([][]frontend.Variable, legs),
		KeysPerLeg:   keysPerLeg,
		VerifyingKey: vk,
	}
	for i := range c.Proofs {
		c.Proofs[i] = stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs)
		c.Witnesses[i] = stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs)
		c.Preimages[i] = make([]frontend.Variable, PreimageLen(keysPerLeg))
	}
	return c, nil
}

func (c *Circuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}

	keyStart := PrefixLen
	keyEnd := PrefixLen + KeyFields*c.KeysPerLeg

	for i := range c.Proofs {
		// The legs are the bytes the zone verifies on chain, so their BSB22
		// challenge follows the native RFC 9380 derivation. The key-encryption
		// circuit emulates P-256, which commits, so this is load bearing.
		if err := verifier.AssertProof(
			c.VerifyingKey, c.Proofs[i], c.Witnesses[i], stdgroth16.WithNativeHashToField(),
		); err != nil {
			return fmt.Errorf("leg %d: %w", i, err)
		}
		if len(c.Witnesses[i].Public) != 1 {
			return fmt.Errorf("leg %d has %d public inputs, want 1", i, len(c.Witnesses[i].Public))
		}
		if _, err := gadget.OpenPublicInput(api, field, &c.Witnesses[i].Public[0], c.Preimages[i]); err != nil {
			return fmt.Errorf("leg %d: %w", i, err)
		}

		if i == 0 {
			continue
		}
		// One account, so every field outside the recipient triples is the same
		// in every leg. The fold chain reads these from leg 0 only, so without
		// these assertions a leg could encrypt a different viewing secret, bind
		// a different prior state, or publish a different nullifier, and the
		// chain the program checks would still match.
		for j := 0; j < PrefixLen; j++ {
			api.AssertIsEqual(c.Preimages[i][j], c.Preimages[0][j])
		}
		for j := 0; j < SuffixLen; j++ {
			api.AssertIsEqual(c.Preimages[i][keyEnd+j], c.Preimages[0][keyEnd+j])
		}
	}

	// The chain a single circuit over the union would expose. The shared fields
	// come once, then every leg's recipient triples in leg order.
	chain := make([]frontend.Variable, 0, PrefixLen+KeyFields*c.KeysPerLeg*len(c.Proofs)+SuffixLen)
	chain = append(chain, c.Preimages[0][:PrefixLen]...)
	for i := range c.Preimages {
		chain = append(chain, c.Preimages[i][keyStart:keyEnd]...)
	}
	chain = append(chain, c.Preimages[0][keyEnd:]...)

	api.AssertIsEqual(c.FoldInputHash, gadget.HashChain(api, chain))
	return nil
}

func (c *Circuit) validateLayout() error {
	if len(c.Proofs) != len(c.Witnesses) || len(c.Proofs) != len(c.Preimages) {
		return fmt.Errorf("%d proofs, %d witnesses, %d preimages",
			len(c.Proofs), len(c.Witnesses), len(c.Preimages))
	}
	if len(c.Proofs) < 2 {
		return fmt.Errorf("%d legs", len(c.Proofs))
	}
	if c.KeysPerLeg < 1 {
		return fmt.Errorf("%d keys per leg", c.KeysPerLeg)
	}
	want := PreimageLen(c.KeysPerLeg)
	for i, preimage := range c.Preimages {
		if len(preimage) != want {
			return fmt.Errorf("leg %d preimage is %d fields, want %d", i, len(preimage), want)
		}
	}
	return nil
}
