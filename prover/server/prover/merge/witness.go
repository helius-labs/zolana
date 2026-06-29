package merge

import (
	mergecircuit "zolana/prover/circuits/spp_merge"
	transaction "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover/common"

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
// The merge-zone rail (CircuitType == MergeZoneCircuitType) is assigned onto the
// policy-zone circuit, which additionally carries the top-level public
// ZoneProgramID; every other rail uses the default merge circuit.
func (p *MergeParameters) CreateWitness() (frontend.Circuit, error) {
	if p.CircuitType == common.MergeZoneCircuitType {
		return p.createZoneWitness(), nil
	}
	return p.createDefaultWitness(), nil
}

func (p *MergeParameters) createDefaultWitness() *mergecircuit.Circuit {
	circuit := mergecircuit.NewMergeCircuit()

	circuit.P256Pub = transaction.P256PublicKey{
		X: emulated.ValueOf[emulated.P256Fp](p.P256PubX),
		Y: emulated.ValueOf[emulated.P256Fp](p.P256PubY),
	}
	circuit.OwnerPkHash = p.OwnerPkHash
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
		circuit.Inputs[i] = p.inputAt(i)
	}

	circuit.Output = mergecircuit.Output{
		Utxo: utxoFields(p.Output.Utxo),
		Hash: p.Output.Hash,
	}

	return circuit
}

func (p *MergeParameters) createZoneWitness() *mergecircuit.ZoneCircuit {
	circuit := mergecircuit.NewMergeZoneCircuit()

	circuit.P256Pub = transaction.P256PublicKey{
		X: emulated.ValueOf[emulated.P256Fp](p.P256PubX),
		Y: emulated.ValueOf[emulated.P256Fp](p.P256PubY),
	}
	circuit.OwnerPkHash = p.OwnerPkHash
	circuit.UserNullifierPk = p.UserNullifierPk
	circuit.UserNullifierSecret = p.UserNullifierSecret
	circuit.TxViewingSk = p.TxViewingSk
	for i := 0; i < len(circuit.UserViewingPubkey); i++ {
		circuit.UserViewingPubkey[i] = p.UserViewingPubkey[i]
	}
	circuit.ExternalDataHash = p.ExternalDataHash
	circuit.PrivateTxHash = p.PrivateTxHash
	circuit.ZoneProgramID = p.ZoneProgramID
	circuit.PublicInputHash = p.PublicInputHash

	for i := range p.Inputs {
		circuit.Inputs[i] = p.inputAt(i)
	}

	circuit.Output = mergecircuit.Output{
		Utxo: utxoFields(p.Output.Utxo),
		Hash: p.Output.Hash,
	}

	return circuit
}

func (p *MergeParameters) inputAt(i int) mergecircuit.Input {
	in := p.Inputs[i]
	statePath := make([]frontend.Variable, len(in.StatePathElements))
	for j := range in.StatePathElements {
		statePath[j] = in.StatePathElements[j]
	}
	nullifierPath := make([]frontend.Variable, len(in.NullifierLowPathElements))
	for j := range in.NullifierLowPathElements {
		nullifierPath[j] = in.NullifierLowPathElements[j]
	}
	return mergecircuit.Input{
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
