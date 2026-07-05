package squadszone

import (
	"math/big"

	zonecircuit "zolana/prover/circuits/squads/zone"
	zoneutils "zolana/prover/circuits/zone-utils"

	"github.com/consensys/gnark/std/math/emulated"
)

func utxoFields(u UtxoParams) zoneutils.Utxo {
	return zoneutils.Utxo{
		OwnerHash:       u.OwnerHash,
		Asset:           u.Asset,
		Amount:          u.Amount,
		Blinding:        u.Blinding,
		ProgramDataHash: u.ProgramDataHash,
		ZoneDataHash:    u.ZoneDataHash,
		ZoneProgramID:   u.ZoneProgramID,
	}
}

// CreateWitness assigns the pre-computed parameters onto the squads zone circuit.
// It performs no hashing/encryption — every signal is taken verbatim from the
// client-supplied params. All fields (including the recipient, which is
// unconstrained on the withdrawal shape) must be assigned for gnark.
func (p *ZoneParameters) CreateWitness() (*zonecircuit.Circuit, error) {
	circuit, err := newZoneCircuit(p.NInputs, p.NOutputs)
	if err != nil {
		return nil, err
	}

	for i := range p.Inputs {
		circuit.Transaction.Inputs[i] = utxoFields(p.Inputs[i])
	}
	for i := range circuit.InputsDummy {
		if i < len(p.InputsDummy) && p.InputsDummy[i] != nil {
			circuit.InputsDummy[i] = p.InputsDummy[i]
		} else {
			circuit.InputsDummy[i] = big.NewInt(0)
		}
	}
	for i := range p.Outputs {
		circuit.Transaction.Outputs[i] = utxoFields(p.Outputs[i])
	}
	circuit.Transaction.ExternalDataHash = p.ExternalDataHash

	circuit.Sender.Account.Public.Owner = p.Sender.Owner
	circuit.Sender.Account.Public.SharedViewingSecretKeyCommitment = p.Sender.SharedViewingSecretKeyCommitment
	circuit.Sender.Account.Public.NullifierPubkey = p.Sender.NullifierPubkey
	circuit.Sender.Account.Private.NullifierSecret = p.Sender.NullifierSecret
	circuit.Sender.Account.Private.SharedViewingSecretKey = emulated.ValueOf[emulated.P256Fr](p.Sender.SharedViewingSecretKey)

	circuit.Recipient.Owner = p.Recipient.Owner
	circuit.Recipient.NullifierPubkey = p.Recipient.NullifierPubkey
	for i := 0; i < 65; i++ {
		circuit.Recipient.ViewingPubkey[i] = p.Recipient.ViewingPubkey[i]
	}

	circuit.Proposal.Amount = p.Proposal.Amount
	circuit.Proposal.Recipient = p.Proposal.Recipient
	circuit.Proposal.Blinding = p.Proposal.Blinding
	circuit.Proposal.PublicAmount = p.Proposal.PublicAmount

	circuit.EnableProposalHash = p.EnableProposalHash
	circuit.PublicAmount = p.PublicAmount
	circuit.PublicInputHash = p.PublicInputHash

	return circuit, nil
}
