package transfereddsaonly

import (
	"fmt"
	"math/big"

	customring "zolana/prover/circuits/spp_transaction/custom"
	defaultring "zolana/prover/circuits/spp_transaction/default"
	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"

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
		RingDataHash:  u.RingDataHash,
		RingProgramID: u.RingProgramID,
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
		TreeSlot:                 in.TreeSlot,
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
	treeSlots          []txcircuit.TreeSlot
	inputOwnerPkHashes []frontend.Variable
	outputs            []txcircuit.UtxoCircuitFields
	outputHashes       []frontend.Variable
	publicAssets       [txcircuit.NPublicSlots]frontend.Variable
	publicAmounts      [txcircuit.NPublicSlots]frontend.Variable
}

// treeSlotsWitness assigns the public tree slots. The count is fixed by the
// compiled skeleton, and an unused slot is all zero, so a nil value assigns as
// zero rather than leaving the signal unset.
func treeSlotsWitness(slots []common.TreeSlotParams) ([]txcircuit.TreeSlot, error) {
	if len(slots) != txcircuit.InputTrees {
		return nil, fmt.Errorf(
			"spp: tree slot count mismatch: got %d want %d",
			len(slots), txcircuit.InputTrees,
		)
	}
	out := make([]txcircuit.TreeSlot, len(slots))
	for k, slot := range slots {
		out[k] = txcircuit.TreeSlot{
			ID:            orZero(slot.ID),
			UtxoRoot:      orZero(slot.UtxoRoot),
			NullifierRoot: orZero(slot.NullifierRoot),
		}
	}
	return out, nil
}

func buildWitnessCore(
	inputs []InputParams,
	outputs []OutputParams,
	treeSlots []common.TreeSlotParams,
	publicAssets, publicAmounts []*big.Int,
) (witnessCore, error) {
	if len(publicAssets) != txcircuit.NPublicSlots || len(publicAmounts) != txcircuit.NPublicSlots {
		return witnessCore{}, fmt.Errorf(
			"spp: public slot count mismatch: got %d assets and %d amounts, want %d",
			len(publicAssets), len(publicAmounts), txcircuit.NPublicSlots,
		)
	}
	slots, err := treeSlotsWitness(treeSlots)
	if err != nil {
		return witnessCore{}, err
	}
	core := witnessCore{
		inputs:             make([]txcircuit.Input, len(inputs)),
		nullifiers:         make([]frontend.Variable, len(inputs)),
		treeSlots:          slots,
		inputOwnerPkHashes: make([]frontend.Variable, len(inputs)),
		outputs:            make([]txcircuit.UtxoCircuitFields, len(outputs)),
		outputHashes:       make([]frontend.Variable, len(outputs)),
	}
	for i, in := range inputs {
		core.inputs[i] = inputWitness(in)
		core.nullifiers[i] = in.Nullifier
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
	core, err := buildWitnessCore(p.Inputs, p.Outputs, p.TreeSlots, p.PublicAssets, p.PublicAmounts)
	if err != nil {
		return nil, err
	}
	shape := txcircuit.Shape{NInputs: int(p.NInputs), NOutputs: int(p.NOutputs)}
	wantSigners := shape.SignerWidth()
	if p.Variant == RingAuthorityVariant {
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
	if p.Variant == RingAuthorityVariant {
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
		return &defaultring.DefaultRingEddsaOnlyCircuit{
			Shape: shape,
			Public: defaultring.DefaultRingEddsaOnlyPublic{
				Nullifiers:          core.nullifiers,
				OutputHashes:        core.outputHashes,
				TreeSlots:           core.treeSlots,
				OutputTreeID:        p.OutputTreeID,
				PrivateTxHash:       p.PrivateTxHash,
				ExternalDataHash:    p.ExternalDataHash,
				PublicAssets:        core.publicAssets,
				PublicAmounts:       core.publicAmounts,
				AllowDummyInputs:    p.AllowDummyInputs,
				SignerPkHashes:      signerPkHashes,
				OutputOwnerPkHashes: publishedOutputOwnerPkHashes,
				PublicInputHash:     p.PublicInputHash,
			},
			Private: defaultring.DefaultRingEddsaOnlyPrivate{
				Inputs:             core.inputs,
				InputOwnerPkHashes: core.inputOwnerPkHashes,
				Outputs:            core.outputs,
				OutputNullifierPks: outputNullifierPks,
				BlindingSeed:       p.BlindingSeed,
			},
		}, nil
	case RingAuthorityVariant:
		return &customring.CustomRingAuthorityCircuit{
			Shape: shape,
			Public: customring.CustomRingAuthorityPublic{
				Nullifiers:       core.nullifiers,
				OutputHashes:     core.outputHashes,
				TreeSlots:        core.treeSlots,
				OutputTreeID:     p.OutputTreeID,
				PrivateTxHash:    p.PrivateTxHash,
				ExternalDataHash: p.ExternalDataHash,
				PublicAssets:     core.publicAssets,
				PublicAmounts:    core.publicAmounts,
				RingProgramID:    p.RingProgramID,
				SignerPkHashes:   signerPkHashes,
				AllowDummyInputs: p.AllowDummyInputs,
				PublicInputHash:  p.PublicInputHash,
			},
			Private: customring.CustomRingAuthorityPrivate{
				Inputs:             core.inputs,
				InputOwnerPkHashes: core.inputOwnerPkHashes,
				Outputs:            core.outputs,
				BlindingSeed:       p.BlindingSeed,
			},
		}, nil
	default:
		outputOwnerPkHashes := make([]frontend.Variable, len(p.Outputs))
		outputNullifierPks := make([]frontend.Variable, len(p.Outputs))
		for i, out := range p.Outputs {
			outputOwnerPkHashes[i] = orZero(out.OwnerPkHash)
			outputNullifierPks[i] = orZero(out.NullifierPk)
		}
		return &customring.CustomRingEddsaOnlyCircuit{
			Shape: shape,
			Public: customring.CustomRingEddsaOnlyPublic{
				Nullifiers:                   core.nullifiers,
				OutputHashes:                 core.outputHashes,
				TreeSlots:                    core.treeSlots,
				OutputTreeID:                 p.OutputTreeID,
				PrivateTxHash:                p.PrivateTxHash,
				ExternalDataHash:             p.ExternalDataHash,
				PublicAssets:                 core.publicAssets,
				PublicAmounts:                core.publicAmounts,
				RingProgramID:                p.RingProgramID,
				AllowDummyInputs:             p.AllowDummyInputs,
				SignerPkHashes:               signerPkHashes,
				PublishedOutputOwnerPkHashes: publishedOutputOwnerPkHashes,
				PublicInputHash:              p.PublicInputHash,
			},
			Private: customring.CustomRingEddsaOnlyPrivate{
				Inputs:              core.inputs,
				InputOwnerPkHashes:  core.inputOwnerPkHashes,
				Outputs:             core.outputs,
				OutputOwnerPkHashes: outputOwnerPkHashes,
				OutputNullifierPks:  outputNullifierPks,
				BlindingSeed:        p.BlindingSeed,
			},
		}, nil
	}
}

// orZero returns big.NewInt(0) for a nil pointer so gnark always sees an
// assigned witness value. Public output-tag fields are absent on anonymous
// ring-authority params.
func orZero(x *big.Int) *big.Int {
	if x == nil {
		return big.NewInt(0)
	}
	return x
}
