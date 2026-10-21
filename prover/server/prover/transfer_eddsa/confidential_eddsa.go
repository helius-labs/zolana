package transfereddsa

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	defaultring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/default"
	txcircuit "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// confidentialEddsaSigners is the number of in-circuit verified owners every
// transfer_confidential_eddsa key proves; CircuitId::ConfidentialEddsa carries one.
const confidentialEddsaSigners = 1

// ConfidentialEddsaTransferParameters is the flat witness for
// DefaultRingConfidentialInCircuitEddsaCircuit: the default confidential
// transfer plus the owner's Ed25519 key and signature over the transact
// message digest, given as two 128-bit limbs.
type ConfidentialEddsaTransferParameters struct {
	TransferParameters

	OwnerPublicKey  [32]byte
	OwnerSignature  [64]byte
	MessageHashLow  *big.Int
	MessageHashHigh *big.Int
}

type ConfidentialEddsaTransferParametersJSON struct {
	TransferParametersJSON
	OwnerPublicKey  string `json:"ownerPublicKey"`
	OwnerSignature  string `json:"ownerSignature"`
	MessageHashLow  string `json:"messageHashLow"`
	MessageHashHigh string `json:"messageHashHigh"`
}

func (p *ConfidentialEddsaTransferParameters) MarshalJSON() ([]byte, error) {
	base := p.TransferParameters
	base.Variant = ConfidentialVariant
	encoded := base.CreateTransferParametersJSON()
	encoded.CircuitType = common.TransferConfidentialEddsaCircuitType
	return json.Marshal(ConfidentialEddsaTransferParametersJSON{
		TransferParametersJSON: encoded,
		OwnerPublicKey:         "0x" + hex.EncodeToString(p.OwnerPublicKey[:]),
		OwnerSignature:         "0x" + hex.EncodeToString(p.OwnerSignature[:]),
		MessageHashLow:         common.FeHex(p.MessageHashLow),
		MessageHashHigh:        common.FeHex(p.MessageHashHigh),
	})
}

func (p *ConfidentialEddsaTransferParameters) UnmarshalJSON(data []byte) error {
	var params ConfidentialEddsaTransferParametersJSON
	if err := json.Unmarshal(data, &params); err != nil {
		return err
	}
	if params.CircuitType != common.TransferConfidentialEddsaCircuitType {
		return fmt.Errorf("invalid confidential EdDSA transfer circuit type %q", params.CircuitType)
	}
	base := params.TransferParametersJSON
	base.CircuitType = common.TransferConfidentialCircuitType
	if err := p.TransferParameters.UpdateWithJSON(base); err != nil {
		return err
	}
	if err := exactBytes(p.OwnerPublicKey[:], params.OwnerPublicKey); err != nil {
		return fmt.Errorf("ownerPublicKey: %w", err)
	}
	if err := exactBytes(p.OwnerSignature[:], params.OwnerSignature); err != nil {
		return fmt.Errorf("ownerSignature: %w", err)
	}
	var err error
	if p.MessageHashLow, err = common.FeFromHex(params.MessageHashLow); err != nil {
		return err
	}
	if p.MessageHashHigh, err = common.FeFromHex(params.MessageHashHigh); err != nil {
		return err
	}
	return nil
}

func (p *ConfidentialEddsaTransferParameters) CreateWitness() (frontend.Circuit, error) {
	core, err := buildWitnessCore(p.Inputs, p.Outputs, p.TreeSlots, p.PublicAssets, p.PublicAmounts)
	if err != nil {
		return nil, err
	}
	shape := txcircuit.Shape{NInputs: int(p.NInputs), NOutputs: int(p.NOutputs)}
	if len(p.SignerPkHashes) != shape.SignerWidth() {
		return nil, fmt.Errorf(
			"spp: signer pk hash count mismatch: got %d want %d",
			len(p.SignerPkHashes),
			shape.SignerWidth(),
		)
	}
	if len(p.PublishedOutputOwnerPkHashes) != len(p.Outputs) {
		return nil, fmt.Errorf(
			"spp: published output owner pk hash count mismatch: got %d want %d",
			len(p.PublishedOutputOwnerPkHashes),
			len(p.Outputs),
		)
	}
	signerPkHashes := make([]frontend.Variable, len(p.SignerPkHashes))
	for i := range p.SignerPkHashes {
		signerPkHashes[i] = p.SignerPkHashes[i]
	}
	publishedOutputOwnerPkHashes := make([]frontend.Variable, len(p.PublishedOutputOwnerPkHashes))
	for i := range p.PublishedOutputOwnerPkHashes {
		publishedOutputOwnerPkHashes[i] = p.PublishedOutputOwnerPkHashes[i]
	}
	outputNullifierPks := make([]frontend.Variable, len(p.Outputs))
	for i, out := range p.Outputs {
		outputNullifierPks[i] = orZero(out.NullifierPk)
	}
	circuit := &defaultring.DefaultRingConfidentialInCircuitEddsaCircuit{
		CachedInputs: p.Cache.circuitInputs(int(p.NInputs)),
		Shape:        shape,
		NSigners:     confidentialEddsaSigners,
		Public: defaultring.DefaultRingConfidentialInCircuitEddsaPublic{
			Nullifiers:          core.nullifiers,
			OutputHashes:        core.outputHashes,
			TreeSlots:           core.treeSlots,
			OutputTreeID:        p.OutputTreeID,
			PrivateTxHash:       p.PrivateTxHash,
			MessageHashLow:      p.MessageHashLow,
			MessageHashHigh:     p.MessageHashHigh,
			ExternalDataHash:    p.ExternalDataHash,
			PublicAssets:        core.publicAssets,
			PublicAmounts:       core.publicAmounts,
			InputFlags:          p.InputFlags,
			SignerPkHashes:      signerPkHashes,
			OutputOwnerPkHashes: publishedOutputOwnerPkHashes,
			PublicInputHash:     p.PublicInputHash,
		},
		Private: defaultring.DefaultRingConfidentialInCircuitEddsaPrivate{
			Inputs:             core.inputs,
			InputOwnerPkHashes: core.inputOwnerPkHashes,
			Outputs:            core.outputs,
			OutputNullifierPks: outputNullifierPks,
			BlindingSeed:       p.BlindingSeed,
			OwnerPublicKeys:    make([][32]frontend.Variable, confidentialEddsaSigners),
			OwnerSignatures:    make([][64]frontend.Variable, confidentialEddsaSigners),
		},
	}
	for i, b := range p.OwnerPublicKey {
		circuit.Private.OwnerPublicKeys[0][i] = b
	}
	for i, b := range p.OwnerSignature {
		circuit.Private.OwnerSignatures[0][i] = b
	}
	return circuit, nil
}

func R1CSConfidentialEddsaTransfer(nInputs uint32, nOutputs uint32) (constraint.ConstraintSystem, error) {
	circuit, err := defaultring.NewDefaultRingConfidentialInCircuitEddsaCircuit(
		txcircuit.Shape{NInputs: int(nInputs), NOutputs: int(nOutputs)},
		confidentialEddsaSigners,
	)
	if err != nil {
		return nil, err
	}
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		circuit,
		frontend.WithCompressThreshold(300),
	)
}

// SetupConfidentialEddsaTransfer runs trusted setup for the default-ring
// confidential transfer authorized by an in-circuit Ed25519 signature.
func SetupConfidentialEddsaTransfer(nInputs uint32, nOutputs uint32) (*common.TransferProofSystem, error) {
	ccs, err := R1CSConfidentialEddsaTransfer(nInputs, nOutputs)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.TransferProofSystem{
		CircuitType:      common.TransferConfidentialEddsaCircuitType,
		NInputs:          nInputs,
		NOutputs:         nOutputs,
		HasCommitment:    true,
		Confidential:     true,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}
