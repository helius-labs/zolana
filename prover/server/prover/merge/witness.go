package merge

import (
	mergecircuit "zolana/prover/circuits/spp_merge"
	transaction "zolana/prover/circuits/spp_transaction"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func utxoFields(u UtxoParams) transaction.UtxoCircuitFields {
	return transaction.UtxoCircuitFields{
		Domain:        u.Domain,
		Owner:         u.Owner,
		Asset:         u.Asset,
		Amount:        u.Amount,
		Blinding:      u.Blinding,
		DataHash:      u.DataHash,
		ZoneDataHash:  u.ZoneDataHash,
		ZoneProgramID: u.ZoneProgramID,
	}
}

// CreateWitness assigns the pre-computed parameters onto the merge circuit. It
// performs no hashing — every signal is taken verbatim from the client params.
func (p *MergeParameters) CreateWitness() (*mergecircuit.Circuit, error) {
	circuit := mergecircuit.NewMergeCircuit()

	circuit.P256Pub = transaction.P256PublicKey{
		X: emulated.ValueOf[emulated.P256Fp](p.P256PubX),
		Y: emulated.ValueOf[emulated.P256Fp](p.P256PubY),
	}
	circuit.SolanaOwnerPkHash = p.SolanaOwnerPkHash
	circuit.UserNullifierPk = p.UserNullifierPk
	circuit.UserNullifierSecret = p.UserNullifierSecret
	circuit.TxViewingSk = p.TxViewingSk
	for i := 0; i < len(circuit.UserViewingPubkey); i++ {
		circuit.UserViewingPubkey[i] = p.UserViewingPubkey[i]
	}
	circuit.ExternalDataHash = p.ExternalDataHash
	circuit.PrivateTxHash = p.PrivateTxHash
	circuit.PublicInputHash = p.PublicInputHash

	for i := range p.Inputs {
		in := p.Inputs[i]
		statePath := make([]frontend.Variable, len(in.StatePathElements))
		for j := range in.StatePathElements {
			statePath[j] = in.StatePathElements[j]
		}
		nullifierPath := make([]frontend.Variable, len(in.NullifierLowPathElements))
		for j := range in.NullifierLowPathElements {
			nullifierPath[j] = in.NullifierLowPathElements[j]
		}
		circuit.Inputs[i] = mergecircuit.Input{
			Utxo:                     utxoFields(in.Utxo),
			IsDummy:                  in.IsDummy,
			StatePathElements:        statePath,
			StatePathIndex:           in.StatePathIndex,
			NullifierLowValue:        in.NullifierLowValue,
			NullifierNextValue:       in.NullifierNextValue,
			NullifierLowPathElements: nullifierPath,
			NullifierLowPathIndex:    in.NullifierLowPathIndex,
			UtxoTreeRoot:             in.UtxoTreeRoot,
			NullifierTreeRoot:        in.NullifierTreeRoot,
			Nullifier:                in.Nullifier,
		}
	}

	circuit.Output = mergecircuit.Output{
		Utxo: utxoFields(p.Output.Utxo),
		Hash: p.Output.Hash,
	}

	return circuit, nil
}
