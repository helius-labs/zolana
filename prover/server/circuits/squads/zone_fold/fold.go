// Package squads_zone_fold holds the outer circuit that folds several zone
// spends of one account into one proof.
//
// The zone circuit has a key for (1,1) and (2,2) only, so three UTXOs cannot be
// spent together. Each leg keeps its own transaction, and the fold is what
// makes the run one operation. Every leg spends the same account and, on the
// transfer shape, pays the same recipient.
//
// The legs are not a sequence. private_tx_hash binds a leg's whole input and
// output set, so no leg continues another. The predicate between them is
// equality on the two identities the run shares.
//
// The inner verifying key is a compile-time constant, so the outer verifying
// key alone names the leg shape a fold proved.
package squads_zone_fold

import (
	"fmt"

	"zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// The zone circuit's public input is HashChain over these, in this order. The
// four recipient fields are present on the transfer shape only, and the
// proposal hash always comes last. Exported so the prover reads a leg preimage
// by name against this one definition of the order.
const (
	PrivateTxHashIndex = iota
	PublicAmountIndex
	SenderAccountIndex
	SenderCiphertextIndex
	TxViewingPkLoIndex
	TxViewingPkHiIndex
	RecipientAccountIndex
	RecipientCiphertextIndex
	TransferProposalIndex
	TransferPreimageLen
)

// WithdrawalPreimageLen covers the four sender fields then the proposal hash.
const WithdrawalPreimageLen = SenderCiphertextIndex + 2

// TransferOutputs is the output count that selects the transfer shape. Any
// other supported count is a withdrawal.
const TransferOutputs = 2

func PreimageLen(numOutputs int) int {
	if numOutputs == TransferOutputs {
		return TransferPreimageLen
	}
	return WithdrawalPreimageLen
}

func proposalIndex(numOutputs int) int {
	return PreimageLen(numOutputs) - 1
}

type (
	InnerProof        = stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	InnerWitness      = stdgroth16.Witness[sw_bn254.ScalarField]
	InnerVerifyingKey = stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
)

// Circuit proves that every leg verifies, that the legs spend one account, and
// that FoldInputHash commits to the run.
type Circuit struct {
	// The shared identities followed by every leg's own fields, in leg order.
	// The only public input, so the on-chain key keeps the shape the zone
	// already verifies.
	FoldInputHash frontend.Variable `gnark:",public"`

	Proofs    []InnerProof
	Witnesses []InnerWitness
	// Per leg, the zone circuit's public-input preimage. Witnessed, then bound
	// to the proof's public input, so a leg cannot claim a spend it did not
	// prove.
	Preimages [][]frontend.Variable

	// Outputs per leg, 1 for a withdrawal and 2 for a transfer. It matches the
	// inner key, so it is a constant.
	NumOutputs int `gnark:"-"`

	// Excluded from the witness. A key supplied at proving time would let a
	// fold choose which circuit it verified against.
	VerifyingKey InnerVerifyingKey `gnark:"-"`
}

func NewCircuit(legs, numOutputs int, vk InnerVerifyingKey, innerCcs constraint.ConstraintSystem) (*Circuit, error) {
	if legs < 2 {
		return nil, fmt.Errorf("%d legs do not amortize a verification", legs)
	}
	if numOutputs != 1 && numOutputs != TransferOutputs {
		return nil, fmt.Errorf("%d outputs per leg", numOutputs)
	}
	c := &Circuit{
		Proofs:       make([]InnerProof, legs),
		Witnesses:    make([]InnerWitness, legs),
		Preimages:    make([][]frontend.Variable, legs),
		NumOutputs:   numOutputs,
		VerifyingKey: vk,
	}
	for i := range c.Proofs {
		c.Proofs[i] = stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs)
		c.Witnesses[i] = stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs)
		c.Preimages[i] = make([]frontend.Variable, PreimageLen(numOutputs))
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

	transfer := c.NumOutputs == TransferOutputs
	proposal := proposalIndex(c.NumOutputs)

	for i := range c.Proofs {
		// The legs are the bytes the zone verifies on chain, so their BSB22
		// challenge follows the native RFC 9380 derivation. The zone circuit
		// emulates P-256, which commits, so this is load bearing.
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

		// A proposal commits to one recipient amount, so a run under one would
		// deliver it once per leg.
		api.AssertIsEqual(c.Preimages[i][proposal], 0)

		if i == 0 {
			continue
		}
		// One account spends the whole run, and on the transfer shape one
		// recipient receives it. The fold chain reads both from leg 0 only, so
		// without these assertions a leg could spend another account's UTXOs or
		// pay elsewhere, and the chain the program checks would still match.
		api.AssertIsEqual(c.Preimages[i][SenderAccountIndex], c.Preimages[0][SenderAccountIndex])
		if transfer {
			api.AssertIsEqual(c.Preimages[i][RecipientAccountIndex], c.Preimages[0][RecipientAccountIndex])
		}
	}

	chain := []frontend.Variable{c.Preimages[0][SenderAccountIndex]}
	if transfer {
		chain = append(chain, c.Preimages[0][RecipientAccountIndex])
	}
	for _, preimage := range c.Preimages {
		chain = append(chain,
			preimage[PrivateTxHashIndex],
			preimage[PublicAmountIndex],
			preimage[SenderCiphertextIndex],
		)
		if transfer {
			chain = append(chain,
				preimage[TxViewingPkLoIndex],
				preimage[TxViewingPkHiIndex],
				preimage[RecipientCiphertextIndex],
			)
		}
	}

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
	if c.NumOutputs != 1 && c.NumOutputs != TransferOutputs {
		return fmt.Errorf("%d outputs per leg", c.NumOutputs)
	}
	want := PreimageLen(c.NumOutputs)
	for i, preimage := range c.Preimages {
		if len(preimage) != want {
			return fmt.Errorf("leg %d preimage is %d fields, want %d", i, len(preimage), want)
		}
	}
	return nil
}
