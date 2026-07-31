package transfereddsaonly

import (
	"fmt"
	"math/big"

	customzone "zolana/prover/circuits/spp_transaction/custom"
	defaultzone "zolana/prover/circuits/spp_transaction/default"
	txcircuit "zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/frontend"
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

// witnessCore carries the assignment pieces shared by every Solana-only
// variant: the private per-slot witnesses and the hoisted public arrays.
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

// CreateWitness assigns the pre-computed parameters onto the Solana-only
// spp_transaction circuit variant selected by Variant. This rail has no P256
// witness at all. No hashing.
func (p *TransferParameters) CreateWitness() (frontend.Circuit, error) {
	core, err := buildWitnessCore(p.Inputs, p.Outputs, p.PublicAssets, p.PublicAmounts)
	if err != nil {
		return nil, err
	}
	shape := txcircuit.Shape{NInputs: int(p.NInputs), NOutputs: int(p.NOutputs)}
	wantSigners := int(p.NInputs) + 1
	if p.Variant == ZoneAuthorityVariant {
		wantSigners = 1
	}
	if len(p.SignerPkHashes) != wantSigners {
		return nil, fmt.Errorf(
			"spp: signer pk hash count mismatch: got %d want %d",
			len(p.SignerPkHashes),
			wantSigners,
		)
	}
	signerPkHashes := make([]frontend.Variable, len(p.SignerPkHashes))
	for i := range p.SignerPkHashes {
		signerPkHashes[i] = p.SignerPkHashes[i]
	}
	wantPublishedOwners := len(p.Outputs)
	if p.Variant == ZoneAuthorityVariant {
		wantPublishedOwners = 0
	}
	if len(p.PublishedOutputOwnerPkHashes) != wantPublishedOwners {
		return nil, fmt.Errorf(
			"spp: published output owner pk hash count mismatch: got %d want %d",
			len(p.PublishedOutputOwnerPkHashes),
			wantPublishedOwners,
		)
	}
	publishedOutputOwnerPkHashes := make([]frontend.Variable, len(p.PublishedOutputOwnerPkHashes))
	for i := range p.PublishedOutputOwnerPkHashes {
		publishedOutputOwnerPkHashes[i] = p.PublishedOutputOwnerPkHashes[i]
	}

	switch p.Variant {
	case ConfidentialVariant:
		outputNullifierPks := make([]frontend.Variable, len(p.Outputs))
		for i, out := range p.Outputs {
			outputNullifierPks[i] = orZero(out.NullifierPk)
		}
		return &defaultzone.DefaultZoneEddsaOnlyCircuit{
			Shape: shape,
			Public: defaultzone.DefaultZoneEddsaOnlyPublic{
				Nullifiers:          core.nullifiers,
				OutputHashes:        core.outputHashes,
				UtxoTreeRoots:       core.utxoTreeRoots,
				NullifierTreeRoots:  core.nullifierTreeRoots,
				PrivateTxHash:       p.PrivateTxHash,
				ExternalDataHash:    p.ExternalDataHash,
				PublicAssets:        core.publicAssets,
				PublicAmounts:       core.publicAmounts,
				AllowDummyInputs:    p.AllowDummyInputs,
				SignerPkHashes:      signerPkHashes,
				OutputOwnerPkHashes: publishedOutputOwnerPkHashes,
				PublicInputHash:     p.PublicInputHash,
			},
			Private: defaultzone.DefaultZoneEddsaOnlyPrivate{
				Inputs:             core.inputs,
				InputOwnerPkHashes: core.inputOwnerPkHashes,
				Outputs:            core.outputs,
				OutputNullifierPks: outputNullifierPks,
			},
		}, nil
	case ZoneAuthorityVariant:
		return &customzone.CustomZoneAuthorityCircuit{
			Shape: shape,
			Public: customzone.CustomZoneAuthorityPublic{
				Nullifiers:         core.nullifiers,
				OutputHashes:       core.outputHashes,
				UtxoTreeRoots:      core.utxoTreeRoots,
				NullifierTreeRoots: core.nullifierTreeRoots,
				PrivateTxHash:      p.PrivateTxHash,
				ExternalDataHash:   p.ExternalDataHash,
				PublicAssets:       core.publicAssets,
				PublicAmounts:      core.publicAmounts,
				ZoneProgramID:      p.ZoneProgramID,
				SignerPkHashes:     signerPkHashes,
				AllowDummyInputs:   p.AllowDummyInputs,
				PublicInputHash:    p.PublicInputHash,
			},
			Private: customzone.CustomZoneAuthorityPrivate{
				Inputs:             core.inputs,
				InputOwnerPkHashes: core.inputOwnerPkHashes,
				Outputs:            core.outputs,
			},
		}, nil
	default:
		outputOwnerPkHashes := make([]frontend.Variable, len(p.Outputs))
		outputNullifierPks := make([]frontend.Variable, len(p.Outputs))
		for i, out := range p.Outputs {
			outputOwnerPkHashes[i] = orZero(out.OwnerPkHash)
			outputNullifierPks[i] = orZero(out.NullifierPk)
		}
		return &customzone.CustomZoneEddsaOnlyCircuit{
			Shape: shape,
			Public: customzone.CustomZoneEddsaOnlyPublic{
				Nullifiers:                   core.nullifiers,
				OutputHashes:                 core.outputHashes,
				UtxoTreeRoots:                core.utxoTreeRoots,
				NullifierTreeRoots:           core.nullifierTreeRoots,
				PrivateTxHash:                p.PrivateTxHash,
				ExternalDataHash:             p.ExternalDataHash,
				PublicAssets:                 core.publicAssets,
				PublicAmounts:                core.publicAmounts,
				ZoneProgramID:                p.ZoneProgramID,
				AllowDummyInputs:             p.AllowDummyInputs,
				SignerPkHashes:               signerPkHashes,
				PublishedOutputOwnerPkHashes: publishedOutputOwnerPkHashes,
				PublicInputHash:              p.PublicInputHash,
			},
			Private: customzone.CustomZoneEddsaOnlyPrivate{
				Inputs:              core.inputs,
				InputOwnerPkHashes:  core.inputOwnerPkHashes,
				Outputs:             core.outputs,
				OutputOwnerPkHashes: outputOwnerPkHashes,
				OutputNullifierPks:  outputNullifierPks,
			},
		}, nil
	}
}

// orZero returns big.NewInt(0) for a nil pointer so gnark always sees an
// assigned witness value. Public output-tag fields are absent on anonymous
// zone-authority params.
func orZero(x *big.Int) *big.Int {
	if x == nil {
		return big.NewInt(0)
	}
	return x
}
