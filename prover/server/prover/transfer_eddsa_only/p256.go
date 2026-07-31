package transfereddsaonly

import (
	"encoding/json"
	"fmt"
	"math/big"

	customring "zolana/prover/circuits/spp_transaction/custom"
	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
)

// P256TransferParameters is the flat witness for CustomRingP256Circuit.
type P256TransferParameters struct {
	NInputs  uint32
	NOutputs uint32

	Inputs  []InputParams
	Outputs []OutputParams

	ExternalDataHash *big.Int
	PrivateTxHash    *big.Int

	P256PubX               *big.Int
	P256PubY               *big.Int
	P256SigR               *big.Int
	P256SigS               *big.Int
	P256MessageHashLow     *big.Int
	P256MessageHashHigh    *big.Int
	DefaultP256OwnerPkHash *big.Int

	PublicAssets                 []*big.Int
	PublicAmounts                []*big.Int
	RingProgramID                *big.Int
	SignerPkHashes               []*big.Int
	AllowDummyInputs             *big.Int
	PublishedOutputOwnerPkHashes []*big.Int
	PublicInputHash              *big.Int
}

type P256TransferParametersJSON struct {
	CircuitType                  common.CircuitType `json:"circuitType"`
	NInputs                      uint32             `json:"nInputs"`
	NOutputs                     uint32             `json:"nOutputs"`
	Inputs                       []InputParamsJSON  `json:"inputs"`
	Outputs                      []OutputParamsJSON `json:"outputs"`
	ExternalDataHash             string             `json:"externalDataHash"`
	PrivateTxHash                string             `json:"privateTxHash"`
	P256PubX                     string             `json:"p256PubX"`
	P256PubY                     string             `json:"p256PubY"`
	P256SigR                     string             `json:"p256SigR"`
	P256SigS                     string             `json:"p256SigS"`
	P256MessageHashLow           string             `json:"p256MessageHashLow"`
	P256MessageHashHigh          string             `json:"p256MessageHashHigh"`
	DefaultP256OwnerPkHash       string             `json:"defaultP256OwnerPkHash"`
	PublicAssets                 []string           `json:"publicAssets"`
	PublicAmounts                []string           `json:"publicAmounts"`
	RingProgramID                string             `json:"ringProgramId"`
	SignerPkHashes               []string           `json:"signerPkHashes"`
	AllowDummyInputs             string             `json:"allowDummyInputs"`
	PublishedOutputOwnerPkHashes []string           `json:"publishedOutputOwnerPkHashes"`
	PublicInputHash              string             `json:"publicInputHash"`
}

func (p *P256TransferParameters) MarshalJSON() ([]byte, error) {
	base := (&TransferParameters{
		NInputs:                      p.NInputs,
		NOutputs:                     p.NOutputs,
		Inputs:                       p.Inputs,
		Outputs:                      p.Outputs,
		ExternalDataHash:             p.ExternalDataHash,
		PrivateTxHash:                p.PrivateTxHash,
		PublicAssets:                 p.PublicAssets,
		PublicAmounts:                p.PublicAmounts,
		RingProgramID:                p.RingProgramID,
		SignerPkHashes:               p.SignerPkHashes,
		AllowDummyInputs:             p.AllowDummyInputs,
		PublishedOutputOwnerPkHashes: p.PublishedOutputOwnerPkHashes,
		Variant:                      RingVariant,
		PublicInputHash:              p.PublicInputHash,
	}).CreateTransferParametersJSON()
	return json.Marshal(P256TransferParametersJSON{
		CircuitType:                  common.TransferP256RingCircuitType,
		NInputs:                      base.NInputs,
		NOutputs:                     base.NOutputs,
		Inputs:                       base.Inputs,
		Outputs:                      base.Outputs,
		ExternalDataHash:             base.ExternalDataHash,
		PrivateTxHash:                base.PrivateTxHash,
		P256PubX:                     feHex(p.P256PubX),
		P256PubY:                     feHex(p.P256PubY),
		P256SigR:                     feHex(p.P256SigR),
		P256SigS:                     feHex(p.P256SigS),
		P256MessageHashLow:           feHex(p.P256MessageHashLow),
		P256MessageHashHigh:          feHex(p.P256MessageHashHigh),
		DefaultP256OwnerPkHash:       feHex(p.DefaultP256OwnerPkHash),
		PublicAssets:                 base.PublicAssets,
		PublicAmounts:                base.PublicAmounts,
		RingProgramID:                base.RingProgramID,
		SignerPkHashes:               base.SignerPkHashes,
		AllowDummyInputs:             base.AllowDummyInputs,
		PublishedOutputOwnerPkHashes: base.PublishedOutputOwnerPkHashes,
		PublicInputHash:              base.PublicInputHash,
	})
}

func (p *P256TransferParameters) UnmarshalJSON(data []byte) error {
	var params P256TransferParametersJSON
	if err := json.Unmarshal(data, &params); err != nil {
		return err
	}
	if params.CircuitType != common.TransferP256RingCircuitType {
		return fmt.Errorf("invalid P256 transfer circuit type %q", params.CircuitType)
	}
	base := TransferParameters{}
	if err := base.UpdateWithJSON(TransferParametersJSON{
		CircuitType:                  common.TransferRingCircuitType,
		NInputs:                      params.NInputs,
		NOutputs:                     params.NOutputs,
		Inputs:                       params.Inputs,
		Outputs:                      params.Outputs,
		ExternalDataHash:             params.ExternalDataHash,
		PrivateTxHash:                params.PrivateTxHash,
		PublicAssets:                 params.PublicAssets,
		PublicAmounts:                params.PublicAmounts,
		RingProgramID:                params.RingProgramID,
		SignerPkHashes:               params.SignerPkHashes,
		AllowDummyInputs:             params.AllowDummyInputs,
		PublishedOutputOwnerPkHashes: params.PublishedOutputOwnerPkHashes,
		PublicInputHash:              params.PublicInputHash,
	}); err != nil {
		return err
	}
	p.NInputs = base.NInputs
	p.NOutputs = base.NOutputs
	p.Inputs = base.Inputs
	p.Outputs = base.Outputs
	p.ExternalDataHash = base.ExternalDataHash
	p.PrivateTxHash = base.PrivateTxHash
	p.PublicAssets = base.PublicAssets
	p.PublicAmounts = base.PublicAmounts
	p.RingProgramID = base.RingProgramID
	p.SignerPkHashes = base.SignerPkHashes
	p.AllowDummyInputs = base.AllowDummyInputs
	p.PublishedOutputOwnerPkHashes = base.PublishedOutputOwnerPkHashes
	p.PublicInputHash = base.PublicInputHash

	var err error
	for target, encoded := range map[**big.Int]string{
		&p.P256PubX:               params.P256PubX,
		&p.P256PubY:               params.P256PubY,
		&p.P256SigR:               params.P256SigR,
		&p.P256SigS:               params.P256SigS,
		&p.P256MessageHashLow:     params.P256MessageHashLow,
		&p.P256MessageHashHigh:    params.P256MessageHashHigh,
		&p.DefaultP256OwnerPkHash: params.DefaultP256OwnerPkHash,
	} {
		if *target, err = feFromHex(encoded); err != nil {
			return err
		}
	}
	return nil
}

func (p *P256TransferParameters) ValidateShape() error {
	return (&TransferParameters{
		NInputs:  p.NInputs,
		NOutputs: p.NOutputs,
		Inputs:   p.Inputs,
		Outputs:  p.Outputs,
	}).ValidateShape()
}

func (p *P256TransferParameters) CreateWitness() (frontend.Circuit, error) {
	core, err := buildWitnessCore(p.Inputs, p.Outputs, p.PublicAssets, p.PublicAmounts)
	if err != nil {
		return nil, err
	}
	if len(p.SignerPkHashes) != int(p.NInputs)+1 {
		return nil, fmt.Errorf(
			"spp: signer pk hash count mismatch: got %d want %d",
			len(p.SignerPkHashes),
			p.NInputs+1,
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
	outputOwnerPkHashes := make([]frontend.Variable, len(p.Outputs))
	outputNullifierPks := make([]frontend.Variable, len(p.Outputs))
	for i, out := range p.Outputs {
		outputOwnerPkHashes[i] = orZero(out.OwnerPkHash)
		outputNullifierPks[i] = orZero(out.NullifierPk)
	}
	return &customring.CustomRingP256Circuit{
		Shape: txcircuit.Shape{NInputs: int(p.NInputs), NOutputs: int(p.NOutputs)},
		Public: customring.CustomRingP256Public{
			Nullifiers:                   core.nullifiers,
			OutputHashes:                 core.outputHashes,
			UtxoTreeRoots:                core.utxoTreeRoots,
			NullifierTreeRoots:           core.nullifierTreeRoots,
			PrivateTxHash:                p.PrivateTxHash,
			P256MessageHashLow:           p.P256MessageHashLow,
			P256MessageHashHigh:          p.P256MessageHashHigh,
			DefaultP256OwnerPkHash:       p.DefaultP256OwnerPkHash,
			ExternalDataHash:             p.ExternalDataHash,
			PublicAssets:                 core.publicAssets,
			PublicAmounts:                core.publicAmounts,
			RingProgramID:                p.RingProgramID,
			AllowDummyInputs:             p.AllowDummyInputs,
			SignerPkHashes:               signerPkHashes,
			PublishedOutputOwnerPkHashes: publishedOutputOwnerPkHashes,
			PublicInputHash:              p.PublicInputHash,
		},
		Private: customring.CustomRingP256Private{
			Inputs:              core.inputs,
			InputOwnerPkHashes:  core.inputOwnerPkHashes,
			Outputs:             core.outputs,
			OutputOwnerPkHashes: outputOwnerPkHashes,
			OutputNullifierPks:  outputNullifierPks,
			P256Pub: customring.P256PublicKey{
				X: emulated.ValueOf[emulated.P256Fp](p.P256PubX),
				Y: emulated.ValueOf[emulated.P256Fp](p.P256PubY),
			},
			P256Sig: customring.P256Signature{
				R: emulated.ValueOf[emulated.P256Fr](p.P256SigR),
				S: emulated.ValueOf[emulated.P256Fr](p.P256SigS),
			},
		},
	}, nil
}

func R1CSP256Transfer(nInputs uint32, nOutputs uint32) (constraint.ConstraintSystem, error) {
	circuit, err := customring.NewCustomRingP256Circuit(
		txcircuit.Shape{NInputs: int(nInputs), NOutputs: int(nOutputs)},
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

func SetupP256Transfer(nInputs uint32, nOutputs uint32) (*common.TransferProofSystem, error) {
	ccs, err := R1CSP256Transfer(nInputs, nOutputs)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.TransferProofSystem{
		CircuitType:      common.TransferP256RingCircuitType,
		NInputs:          nInputs,
		NOutputs:         nOutputs,
		RequiresP256:     true,
		Confidential:     true,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}

func ProveP256Transfer(ps *common.TransferProofSystem, params *P256TransferParameters) (*common.Proof, error) {
	if params == nil {
		panic("params cannot be nil")
	}
	if err := params.ValidateShape(); err != nil {
		return nil, err
	}
	assignment, err := params.CreateWitness()
	if err != nil {
		return nil, fmt.Errorf("error creating P256 circuit witness: %w", err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("error creating P256 witness: %w", err)
	}
	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	if err != nil {
		return nil, fmt.Errorf("error proving P256 transfer: %w", err)
	}
	return &common.Proof{Proof: proof}, nil
}
