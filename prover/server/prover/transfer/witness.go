package transfer

import (
	"fmt"
	"math/big"

	customzone "zolana/prover/circuits/spp_transaction/custom"
	defaultzone "zolana/prover/circuits/spp_transaction/default"
	txcircuit "zolana/prover/circuits/spp_transaction/shared"

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

// inputWitness maps one pre-computed input onto the private spend witness.
func inputWitness(in InputParams) txcircuit.Input {
	statePath := make([]frontend.Variable, len(in.StatePathElements))
	for j := range in.StatePathElements {
		statePath[j] = in.StatePathElements[j]
	}
	nullifierPath := make([]frontend.Variable, len(in.NullifierLowPathElements))
	for j := range in.NullifierLowPathElements {
		nullifierPath[j] = in.NullifierLowPathElements[j]
	}
	return txcircuit.Input{
		Utxo:                     utxoFields(in.Utxo),
		StatePathElements:        statePath,
		StatePathIndex:           in.StatePathIndex,
		NullifierLowValue:        in.NullifierLowValue,
		NullifierNextValue:       in.NullifierNextValue,
		NullifierLowPathElements: nullifierPath,
		NullifierLowPathIndex:    in.NullifierLowPathIndex,
		NullifierSecret:          in.NullifierSecret,
	}
}

// witnessCore carries the assignment pieces shared by every transfer variant:
// the private per-slot witnesses and the hoisted public arrays.
type witnessCore struct {
	inputs             []txcircuit.Input
	nullifiers         []frontend.Variable
	utxoTreeRoots      []frontend.Variable
	nullifierTreeRoots []frontend.Variable
	inputOwnerPkHashes []frontend.Variable
	outputs            []txcircuit.UtxoCircuitFields
	outputHashes       []frontend.Variable
	publicAssets       [txcircuit.NPublicSlots]frontend.Variable
	publicAmounts      [txcircuit.NPublicSlots]frontend.Variable
}

func buildWitnessCore(inputs []InputParams, outputs []OutputParams, publicAssets, publicAmounts []*big.Int) (witnessCore, error) {
	if len(publicAssets) != txcircuit.NPublicSlots || len(publicAmounts) != txcircuit.NPublicSlots {
		return witnessCore{}, fmt.Errorf(
			"spp: public slot count mismatch: got %d assets and %d amounts, want %d",
			len(publicAssets), len(publicAmounts), txcircuit.NPublicSlots,
		)
	}
	core := witnessCore{
		inputs:             make([]txcircuit.Input, len(inputs)),
		nullifiers:         make([]frontend.Variable, len(inputs)),
		utxoTreeRoots:      make([]frontend.Variable, len(inputs)),
		nullifierTreeRoots: make([]frontend.Variable, len(inputs)),
		inputOwnerPkHashes: make([]frontend.Variable, len(inputs)),
		outputs:            make([]txcircuit.UtxoCircuitFields, len(outputs)),
		outputHashes:       make([]frontend.Variable, len(outputs)),
	}
	for i, in := range inputs {
		core.inputs[i] = inputWitness(in)
		core.nullifiers[i] = in.Nullifier
		core.utxoTreeRoots[i] = in.UtxoTreeRoot
		core.nullifierTreeRoots[i] = in.NullifierTreeRoot
		core.inputOwnerPkHashes[i] = in.OwnerPkHash
	}
	for i, out := range outputs {
		core.outputs[i] = utxoFields(out.Utxo)
		core.outputHashes[i] = out.Hash
	}
	for i := 0; i < txcircuit.NPublicSlots; i++ {
		core.publicAssets[i] = publicAssets[i]
		core.publicAmounts[i] = publicAmounts[i]
	}
	return core, nil
}

// CreateWitness assigns the pre-computed parameters onto the P256-capable
// spp_transaction circuit variant selected by Confidential. It performs no
// hashing — every signal is taken verbatim from the client-supplied params.
func (p *TransferParameters) CreateWitness() (frontend.Circuit, error) {
	core, err := buildWitnessCore(p.Inputs, p.Outputs, p.PublicAssets, p.PublicAmounts)
	if err != nil {
		return nil, err
	}
	shape := txcircuit.Shape{NInputs: int(p.NInputs), NOutputs: int(p.NOutputs)}
	p256Pub := txcircuit.P256PublicKey{
		X: emulated.ValueOf[emulated.P256Fp](p.P256PubX),
		Y: emulated.ValueOf[emulated.P256Fp](p.P256PubY),
	}
	p256Sig := txcircuit.P256Signature{
		R: emulated.ValueOf[emulated.P256Fr](p.P256SigR),
		S: emulated.ValueOf[emulated.P256Fr](p.P256SigS),
	}

	if p.Confidential {
		outputOwnerPkHashes := make([]frontend.Variable, len(p.Outputs))
		outputNullifierPks := make([]frontend.Variable, len(p.Outputs))
		for i, out := range p.Outputs {
			outputOwnerPkHashes[i] = orZero(out.OwnerPkHash)
			outputNullifierPks[i] = orZero(out.NullifierPk)
		}
		return &defaultzone.DefaultZoneP256Circuit{
			Shape: shape,
			Public: defaultzone.DefaultZoneP256Public{
				Nullifiers:          core.nullifiers,
				OutputHashes:        core.outputHashes,
				UtxoTreeRoots:       core.utxoTreeRoots,
				NullifierTreeRoots:  core.nullifierTreeRoots,
				PrivateTxHash:       p.PrivateTxHash,
				P256MessageHashLow:  p.P256MessageHashLow,
				P256MessageHashHigh: p.P256MessageHashHigh,
				ExternalDataHash:    p.ExternalDataHash,
				PublicAssets:        core.publicAssets,
				PublicAmounts:       core.publicAmounts,
				ZoneProgramID:       p.ZoneProgramID,
				PayerPubkeyHash:     p.PayerPubkeyHash,
				AllowDummyInputs:    p.AllowDummyInputs,
				InputOwnerPkHashes:  core.inputOwnerPkHashes,
				OutputOwnerPkHashes: outputOwnerPkHashes,
				P256SigningPkField:  orZero(p.P256SigningPkField),
				PublicInputHash:     p.PublicInputHash,
			},
			Private: defaultzone.DefaultZoneP256Private{
				Inputs:             core.inputs,
				Outputs:            core.outputs,
				OutputNullifierPks: outputNullifierPks,
				P256Pub:            p256Pub,
				P256Sig:            p256Sig,
			},
		}, nil
	}

	return &customzone.CustomZoneP256Circuit{
		Shape: shape,
		Public: customzone.CustomZoneP256Public{
			Nullifiers:          core.nullifiers,
			OutputHashes:        core.outputHashes,
			UtxoTreeRoots:       core.utxoTreeRoots,
			NullifierTreeRoots:  core.nullifierTreeRoots,
			PrivateTxHash:       p.PrivateTxHash,
			P256MessageHashLow:  p.P256MessageHashLow,
			P256MessageHashHigh: p.P256MessageHashHigh,
			ExternalDataHash:    p.ExternalDataHash,
			PublicAssets:        core.publicAssets,
			PublicAmounts:       core.publicAmounts,
			ZoneProgramID:       p.ZoneProgramID,
			PayerPubkeyHash:     p.PayerPubkeyHash,
			AllowDummyInputs:    p.AllowDummyInputs,
			InputOwnerPkHashes:  core.inputOwnerPkHashes,
			PublicInputHash:     p.PublicInputHash,
		},
		Private: customzone.CustomZoneP256Private{
			Inputs:  core.inputs,
			Outputs: core.outputs,
			P256Pub: p256Pub,
			P256Sig: p256Sig,
		},
	}, nil
}

// orZero returns big.NewInt(0) for a nil pointer so gnark always sees an assigned
// witness value (the confidential-only fields are absent on anonymous params).
func orZero(x *big.Int) *big.Int {
	if x == nil {
		return big.NewInt(0)
	}
	return x
}
