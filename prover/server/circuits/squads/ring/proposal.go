package squadszone

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	squadsutils "zolana/prover/circuits/squads/utils"
)

var (
	proposalCoreV2Domain = new(big.Int).SetBytes([]byte("ZOLANA/SQUADS/PROPOSAL_CORE/V2"))
	proposalV2Domain     = new(big.Int).SetBytes([]byte("ZOLANA/SQUADS/PROPOSAL/V2"))
)

const (
	proposalWithdrawal = 1
	proposalTransfer   = 2
)

type Proposal struct {
	Amount       frontend.Variable
	Recipient    frontend.Variable
	Asset        frontend.Variable
	Destination  frontend.Variable
	Blinding     frontend.Variable // hides the proposal commitment
	PublicAmount frontend.Variable
}

func (p Proposal) Hash(api frontend.API, operation frontend.Variable) frontend.Variable {
	privateCore := gadget.PoseidonHash(api, []frontend.Variable{
		proposalCoreV2Domain,
		operation,
		p.Amount,
		p.Recipient,
		p.Blinding,
		p.PublicAmount,
	})
	return gadget.PoseidonHash(api, []frontend.Variable{
		proposalV2Domain,
		operation,
		privateCore,
		p.Asset,
		p.Destination,
	})
}

// Constrain binds the committed operation to the transaction when a proposal is
// present (enabled == 1) and returns its hash (0 when disabled). Value
// conservation lives in Sender.Constrain.
func (p Proposal) Constrain(
	api frontend.API,
	tx squadsutils.Transaction,
	inputsDummy []frontend.Variable,
	recipientOutputIndex int,
	hasRecipient bool,
	recipientOwner, publicAmount, enabled frontend.Variable,
) frontend.Variable {
	api.AssertIsBoolean(enabled)

	// A proposal is single-asset, so every real input and every output must carry
	// the approved asset. Dummy input fields remain unconstrained.
	squadsutils.ForceEqualIfEnabled(api, tx.Inputs[0].Asset, p.Asset, enabled)
	for i, dummy := range inputsDummy {
		inputEnabled := api.Mul(enabled, api.Sub(1, dummy))
		squadsutils.ForceEqualIfEnabled(api, tx.Inputs[i+1].Asset, p.Asset, inputEnabled)
	}
	for i := range tx.Outputs {
		squadsutils.ForceEqualIfEnabled(api, tx.Outputs[i].Asset, p.Asset, enabled)
	}

	squadsutils.ForceEqualIfEnabled(api, p.PublicAmount, publicAmount, enabled)

	operation := frontend.Variable(proposalWithdrawal)
	if hasRecipient {
		operation = frontend.Variable(proposalTransfer)
		recipientOutput := tx.Outputs[recipientOutputIndex]
		squadsutils.ForceEqualIfEnabled(api, recipientOutput.OwnerHash, p.Recipient, enabled)
		squadsutils.ForceEqualIfEnabled(api, recipientOutput.Amount, p.Amount, enabled)
		// The account record stores the recipient's owner field, while p.Recipient is
		// the full output owner hash, so both representations are bound.
		squadsutils.ForceEqualIfEnabled(api, p.Destination, recipientOwner, enabled)
	} else {
		// A withdrawal has no recipient UTXO, so the private recipient amount is 0.
		squadsutils.ForceEqualIfEnabled(api, p.Amount, frontend.Variable(0), enabled)
		squadsutils.ForceEqualIfEnabled(api, p.Recipient, frontend.Variable(0), enabled)
	}

	return api.Select(enabled, p.Hash(api, operation), frontend.Variable(0))
}
