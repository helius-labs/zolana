package transfer

import (
	"math/big"

	txcircuit "zolana/prover/circuits/spp_transaction"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func utxoFields(u UtxoParams) txcircuit.UtxoCircuitFields {
	return txcircuit.UtxoCircuitFields{
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

// CreateWitness assigns the pre-computed parameters onto the P256-capable
// spp_transaction circuit. It performs no hashing — every signal is taken
// verbatim from the client-supplied params.
func (p *TransferParameters) CreateWitness() (*txcircuit.Circuit, error) {
	circuit := &txcircuit.Circuit{
		Shape:        txcircuit.Shape{NInputs: int(p.NInputs), NOutputs: int(p.NOutputs)},
		RequiresP256: true,
		Confidential: p.Confidential,
		Inputs:       make([]txcircuit.Input, p.NInputs),
		Outputs:      make([]txcircuit.Output, p.NOutputs),

		P256SigningPkField: orZero(p.P256SigningPkField),
		ExternalDataHash:   p.ExternalDataHash,
		P256Pub: txcircuit.P256PublicKey{
			X: emulated.ValueOf[emulated.P256Fp](p.P256PubX),
			Y: emulated.ValueOf[emulated.P256Fp](p.P256PubY),
		},
		P256Sig: txcircuit.P256Signature{
			R: emulated.ValueOf[emulated.P256Fr](p.P256SigR),
			S: emulated.ValueOf[emulated.P256Fr](p.P256SigS),
		},
		PrivateTxHash:        p.PrivateTxHash,
		P256MessageHashLow:   p.P256MessageHashLow,
		P256MessageHashHigh:  p.P256MessageHashHigh,
		PublicSolAmount:      p.PublicSolAmount,
		PublicSplAmount:      p.PublicSplAmount,
		PublicSplAssetPubkey: p.PublicSplAssetPubkey,
		ZoneProgramID:        p.ZoneProgramID,
		PayerPubkeyHash:      p.PayerPubkeyHash,
		PublicInputHash:      p.PublicInputHash,
	}

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
		circuit.Inputs[i] = txcircuit.Input{
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
			OwnerPkHash:              in.OwnerPkHash,
			NullifierSecret:          in.NullifierSecret,
		}
	}

	for i := range p.Outputs {
		out := p.Outputs[i]
		circuit.Outputs[i] = txcircuit.Output{
			Utxo:        utxoFields(out.Utxo),
			IsDummy:     out.IsDummy,
			Hash:        out.Hash,
			OwnerPkHash: orZero(out.OwnerPkHash),
			NullifierPk: orZero(out.NullifierPk),
		}
	}

	return circuit, nil
}

// orZero returns big.NewInt(0) for a nil pointer so gnark always sees an assigned
// witness value (the confidential-only fields are absent on anonymous params).
func orZero(x *big.Int) *big.Int {
	if x == nil {
		return big.NewInt(0)
	}
	return x
}
