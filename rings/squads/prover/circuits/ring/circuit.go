package squadsring

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"circuits/ringutils"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

const (
	SenderOutputIndex    = 0
	RecipientOutputIndex = 1
)

type Circuit struct {
	NumInputs  int `gnark:"-"`
	NumOutputs int `gnark:"-"`

	// Transaction slots use the SPP domains. Inputs[0] is structurally real: its
	// nullifier seeds the tx_viewing_sk KDF. Later inputs may be dummies; every
	// output is real.
	Transaction ringutils.Transaction

	Sender    Sender
	Recipient Recipient

	Proposal           Proposal
	EnableProposalHash frontend.Variable

	// PublicAmount is the public withdrawn amount (0 for a transfer); a ring
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
		Transaction: ringutils.Transaction{
			Inputs:  make([]ringutils.Utxo, numInputs),
			Outputs: make([]ringutils.Utxo, numOutputs),
		},
	}
}

func (c *Circuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

	c.constrainDomains(api)

	firstNullifier := c.Sender.FirstNullifier(api, c.Transaction)
	txViewingSk, err := c.Sender.DeriveTxViewingSk(api, firstNullifier)
	if err != nil {
		return err
	}
	blindingSeed := DeriveBlindingSeed(api, txViewingSk)
	changeBlinding := transaction.DeriveOutputBlinding(
		api,
		firstNullifier,
		transaction.DeriveOutputBlindingSeed(api, firstNullifier, blindingSeed),
		SenderOutputIndex,
	)
	privateTxBlinding := transaction.DerivePrivateTxBlinding(api, firstNullifier, blindingSeed)

	// NumOutputs is compile-time: a withdrawal (1-out) has no recipient, so its
	// recipient amount is 0 and the recipient constraints are omitted entirely.
	hasRecipient := c.NumOutputs == 2
	recipientAmount := frontend.Variable(0)
	if hasRecipient {
		recipientAmount = c.Transaction.Outputs[RecipientOutputIndex].Amount
	}

	senderCiphertextHash, err := c.Sender.Constrain(api, c.Transaction, txViewingSk, changeBlinding, c.PublicAmount, recipientAmount)
	if err != nil {
		return err
	}

	// Public input chain: private_tx_hash, external_data_hash, public_amount, sender
	// ciphertext, then (transfer only) tx_viewing_pk + recipient account +
	// recipient ciphertext, then the proposal hash.
	chain := []frontend.Variable{
		c.Transaction.PrivateTxHash(api, privateTxBlinding),
		c.Transaction.ExternalDataHash,
		c.PublicAmount,
		c.Sender.Account.Public.Hash(api),
		senderCiphertextHash,
	}

	if hasRecipient {
		// tx_viewing_pk == tx_viewing_sk · G (keypair consistency): derived, not
		// witnessed. Bound into the chain so the recipient derives the same ECDH key.
		var txViewingSkBytes [32]frontend.Variable
		copy(txViewingSkBytes[:], ringutils.FieldToBytesBE(api, txViewingSk, 32))
		txViewingPkComp := ringutils.TaggedPublicKey(api, txViewingSkBytes)
		pkLo, pkHi := ringutils.Pack33To2FECircuit(api, txViewingPkComp)

		recipientCiphertextHash := c.Recipient.Constrain(api, c.Transaction, txViewingSkBytes, txViewingPkComp)
		chain = append(chain, pkLo, pkHi, c.Recipient.Hash(api), recipientCiphertextHash)
	}

	proposalHash := c.Proposal.Constrain(api, c.Transaction, RecipientOutputIndex, hasRecipient, c.PublicAmount, c.EnableProposalHash)
	chain = append(chain, proposalHash)

	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}

func (c *Circuit) validateLayout() error {
	if c.NumInputs < 1 {
		return fmt.Errorf("squads_ring: NumInputs must be >= 1, got %d", c.NumInputs)
	}
	// 1 output = withdrawal (sender change only); 2 = transfer (change + recipient).
	if c.NumOutputs != 1 && c.NumOutputs != 2 {
		return fmt.Errorf("squads_ring: NumOutputs must be 1 (withdrawal) or 2 (transfer), got %d", c.NumOutputs)
	}
	if got := len(c.Transaction.Inputs); got != c.NumInputs {
		return fmt.Errorf("squads_ring: input count mismatch: got %d want %d", got, c.NumInputs)
	}
	if got := len(c.Transaction.Outputs); got != c.NumOutputs {
		return fmt.Errorf("squads_ring: output count mismatch: got %d want %d", got, c.NumOutputs)
	}
	return nil
}

// constrainDomains admits real and dummy inputs but no address slots, pins
// Inputs[0] and every output to a real UTXO, and zeroes a dummy input's amount:
// a dummy slot contributes 0 to private_tx_hash, so nothing else binds its
// fields to the SPP transaction.
func (c *Circuit) constrainDomains(api frontend.API) {
	for _, in := range c.Transaction.Inputs {
		api.AssertIsEqual(
			api.Mul(api.Sub(in.Domain, transaction.DummyDomain), api.Sub(in.Domain, transaction.UtxoDomain)),
			0,
		)
		api.AssertIsEqual(api.Mul(api.Sub(1, ringutils.IsUtxo(api, in)), in.Amount), 0)
	}
	api.AssertIsEqual(c.Transaction.Inputs[0].Domain, transaction.UtxoDomain)
	for _, out := range c.Transaction.Outputs {
		api.AssertIsEqual(out.Domain, transaction.UtxoDomain)
	}
}
