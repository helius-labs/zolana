package squadszone

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/verifiable-encryption/aes"
	zoneutils "zolana/prover/circuits/zone-utils"
	"zolana/prover/circuits/zone-utils/p256"
)

const (
	SenderOutputIndex    = 0
	RecipientOutputIndex = 1
)

type Circuit struct {
	NumInputs  int `gnark:"-"`
	NumOutputs int `gnark:"-"`

	Transaction zoneutils.Transaction

	// InputsDummy[i] flags Inputs[i+1] as a dummy (length NumInputs-1). Inputs[0]
	// is structurally real: its nullifier seeds the tx_viewing_sk KDF. On the
	// (1,1) shape the slice is empty, leaving that constraint system unchanged.
	InputsDummy []frontend.Variable

	Sender    Sender
	Recipient Recipient

	Proposal           Proposal
	EnableProposalHash frontend.Variable

	// PublicAmount is the public withdrawn amount (0 for a transfer); a zone
	// public input, bound on every path including a proposal-less withdrawal.
	PublicAmount frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

// NewTransferCircuit builds the transfer shape: a sender change output plus one
// recipient output verifiably encrypted to the recipient's viewing key.
func NewTransferCircuit(numInputs int) *Circuit {
	return newCircuit(numInputs, 2)
}

// NewWithdrawalCircuit builds the withdrawal shape: a single sender change
// output; the withdrawn value exits publicly and is settled by the SPP proof.
// There is no recipient, so no in-circuit ECDH.
func NewWithdrawalCircuit(numInputs int) *Circuit {
	return newCircuit(numInputs, 1)
}

func newCircuit(numInputs, numOutputs int) *Circuit {
	return &Circuit{
		NumInputs:  numInputs,
		NumOutputs: numOutputs,
		Transaction: zoneutils.Transaction{
			Inputs:  make([]zoneutils.Utxo, numInputs),
			Outputs: make([]zoneutils.Utxo, numOutputs),
		},
		InputsDummy: make([]frontend.Variable, numInputs-1),
	}
}

func (c *Circuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

	for i, dummy := range c.InputsDummy {
		api.AssertIsBoolean(dummy)
		// A dummy input carries no value, so value conservation in
		// Sender.Constrain is unaffected by its remaining fields.
		api.AssertIsEqual(api.Mul(dummy, c.Transaction.Inputs[i+1].Amount), 0)
	}

	g := aes.NewAESGadget(api)

	txViewingSk, err := c.Sender.DeriveTxViewingSk(api, c.Transaction)
	if err != nil {
		return err
	}

	// NumOutputs is compile-time: a withdrawal (1-out) has no recipient, so its
	// recipient amount is 0 and the recipient constraints are omitted entirely.
	hasRecipient := c.NumOutputs == 2
	recipientAmount := frontend.Variable(0)
	if hasRecipient {
		recipientAmount = c.Transaction.Outputs[RecipientOutputIndex].Amount
	}

	senderCiphertextHash, err := c.Sender.Constrain(api, g, c.Transaction, txViewingSk, c.PublicAmount, recipientAmount)
	if err != nil {
		return err
	}

	// Public input chain: private_tx_hash, public_amount, sender account, sender
	// ciphertext, then (transfer only) tx_viewing_pk + recipient account +
	// recipient ciphertext, then the proposal hash.
	chain := []frontend.Variable{
		c.Transaction.HashWithDummies(api, c.InputsDummy),
		c.PublicAmount,
		c.Sender.Account.Public.Hash(api),
		senderCiphertextHash,
	}

	if hasRecipient {
		// tx_viewing_pk == tx_viewing_sk · G (keypair consistency): derived, not
		// witnessed. Bound into the chain so the recipient derives the same ECDH key.
		var txViewingSkBytes [32]frontend.Variable
		copy(txViewingSkBytes[:], zoneutils.FieldToBytesBE(api, txViewingSk, 32))
		txViewingPkComp := p256.CompressPubkey(api, p256.ScalarMulGenerator(api, txViewingSkBytes))
		pkLo, pkHi := zoneutils.Pack33To2FECircuit(api, txViewingPkComp)

		recipientCiphertextHash := c.Recipient.Constrain(api, g, c.Transaction, txViewingSkBytes, txViewingPkComp)
		chain = append(chain, pkLo, pkHi, c.Recipient.Hash(api), recipientCiphertextHash)
	}

	proposalHash := c.Proposal.Constrain(api, c.Transaction, RecipientOutputIndex, hasRecipient, c.PublicAmount, c.EnableProposalHash)
	chain = append(chain, proposalHash)

	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}

func (c *Circuit) validateLayout() error {
	if c.NumInputs < 1 {
		return fmt.Errorf("squads_zone: NumInputs must be >= 1, got %d", c.NumInputs)
	}
	// 1 output = withdrawal (sender change only); 2 = transfer (change + recipient).
	if c.NumOutputs != 1 && c.NumOutputs != 2 {
		return fmt.Errorf("squads_zone: NumOutputs must be 1 (withdrawal) or 2 (transfer), got %d", c.NumOutputs)
	}
	if got := len(c.Transaction.Inputs); got != c.NumInputs {
		return fmt.Errorf("squads_zone: input count mismatch: got %d want %d", got, c.NumInputs)
	}
	if got := len(c.Transaction.Outputs); got != c.NumOutputs {
		return fmt.Errorf("squads_zone: output count mismatch: got %d want %d", got, c.NumOutputs)
	}
	if got := len(c.InputsDummy); got != c.NumInputs-1 {
		return fmt.Errorf("squads_zone: dummy flag count mismatch: got %d want %d", got, c.NumInputs-1)
	}
	return nil
}
