package transfereddsaonly

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

// CreateWitness assigns the pre-computed parameters onto the Solana-only
// spp_transaction circuit. The P256 gadget is not compiled on this rail, so the
// declared-but-unconstrained P256 signals are assigned zero emulated values and
// both P256 message-hash limbs are pinned to 0 (the circuit asserts this). No
// hashing.
func (p *TransferParameters) CreateWitness() (*txcircuit.Circuit, error) {
	circuit := &txcircuit.Circuit{
		Shape:         txcircuit.Shape{NInputs: int(p.NInputs), NOutputs: int(p.NOutputs)},
		RequiresP256:  false,
		Confidential:  p.Variant == ConfidentialVariant,
		ZoneAuthority: p.Variant == ZoneAuthorityVariant,
		Inputs:        make([]txcircuit.Input, p.NInputs),
		Outputs:       make([]txcircuit.Output, p.NOutputs),

		// Solana-only rail has no P256 owner, so the shared signing field is 0.
		P256SigningPkField: big.NewInt(0),
		ExternalDataHash:   p.ExternalDataHash,
		P256Pub: txcircuit.P256PublicKey{
			X: emulated.ValueOf[emulated.P256Fp](big.NewInt(0)),
			Y: emulated.ValueOf[emulated.P256Fp](big.NewInt(0)),
		},
		P256Sig: txcircuit.P256Signature{
			R: emulated.ValueOf[emulated.P256Fr](big.NewInt(0)),
			S: emulated.ValueOf[emulated.P256Fr](big.NewInt(0)),
		},
		PrivateTxHash:        p.PrivateTxHash,
		P256MessageHashLow:   big.NewInt(0),
		P256MessageHashHigh:  big.NewInt(0),
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
