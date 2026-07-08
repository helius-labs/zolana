package squadszone

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	zoneutils "zolana/prover/circuits/zone-utils"
)

type Proposal struct {
	Amount       frontend.Variable
	Recipient    frontend.Variable
	Blinding     frontend.Variable // hides the proposal commitment
	PublicAmount frontend.Variable
}

func (p Proposal) Hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		p.Amount,
		p.Recipient,
		p.Blinding,
		p.PublicAmount,
	})
}

// Constrain binds the committed operation to the transaction when a proposal is
// present (enabled == 1) and returns its hash (0 when disabled). Value
// conservation lives in Sender.Constrain; here public_amount and the recipient
// output are only matched against their committed values.
func (p Proposal) Constrain(api frontend.API, tx zoneutils.Transaction, recipientOutputIndex int, hasRecipient bool, publicAmount, enabled frontend.Variable) frontend.Variable {
	api.AssertIsBoolean(enabled)

	// The committed public_amount must equal the transaction's public_amount input.
	zoneutils.ForceEqualIfEnabled(api, p.PublicAmount, publicAmount, enabled)

	if hasRecipient {
		recipientOutput := tx.Outputs[recipientOutputIndex]
		zoneutils.ForceEqualIfEnabled(api, recipientOutput.OwnerHash, p.Recipient, enabled)
		zoneutils.ForceEqualIfEnabled(api, recipientOutput.Amount, p.Amount, enabled)
	} else {
		// Withdrawal: no recipient UTXO, so the private recipient amount is 0.
		zoneutils.ForceEqualIfEnabled(api, p.Amount, frontend.Variable(0), enabled)
		zoneutils.ForceEqualIfEnabled(api, p.Recipient, frontend.Variable(0), enabled)
	}

	return api.Select(enabled, p.Hash(api), frontend.Variable(0))
}
