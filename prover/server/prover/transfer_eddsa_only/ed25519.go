package transfereddsaonly

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	customring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom"
	txcircuit "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type Ed25519Proof struct {
	System     *common.TransferProofSystem
	Parameters *Ed25519TransferParameters
	Prover     common.Prover
}

// Ed25519TransferParameters is the flat witness for CustomRingEd25519Circuit.
type Ed25519TransferParameters struct {
	NInputs  uint32
	NOutputs uint32

	Inputs       []InputParams
	Outputs      []OutputParams
	TreeSlots    []common.TreeSlotParams
	OutputTreeID *big.Int

	ExternalDataHash *big.Int
	PrivateTxHash    *big.Int
	BlindingSeed     *big.Int

	OwnerPublicKey  [32]byte
	OwnerSignature  [64]byte
	MessageHashLow  *big.Int
	MessageHashHigh *big.Int

	PublicAssets   []*big.Int
	PublicAmounts  []*big.Int
	RingProgramID  *big.Int
	SignerPkHashes []*big.Int
	InputFlags     *big.Int

	Cache CacheSelectionParams

	PublicInputHash *big.Int
}

// Ed25519TransferParametersJSON is the Solana-only wire form plus the hidden
// owner's key, signature and signed digest limbs.
type Ed25519TransferParametersJSON struct {
	TransferParametersJSON
	OwnerPublicKey  string `json:"ownerPublicKey"`
	OwnerSignature  string `json:"ownerSignature"`
	MessageHashLow  string `json:"messageHashLow"`
	MessageHashHigh string `json:"messageHashHigh"`
}

func (p *Ed25519TransferParameters) base() *TransferParameters {
	return &TransferParameters{
		NInputs:          p.NInputs,
		NOutputs:         p.NOutputs,
		Inputs:           p.Inputs,
		Outputs:          p.Outputs,
		TreeSlots:        p.TreeSlots,
		OutputTreeID:     p.OutputTreeID,
		ExternalDataHash: p.ExternalDataHash,
		PrivateTxHash:    p.PrivateTxHash,
		BlindingSeed:     p.BlindingSeed,
		PublicAssets:     p.PublicAssets,
		PublicAmounts:    p.PublicAmounts,
		RingProgramID:    p.RingProgramID,
		SignerPkHashes:   p.SignerPkHashes,
		InputFlags:       p.InputFlags,
		Cache:            p.Cache,
		Variant:          RingVariant,
		PublicInputHash:  p.PublicInputHash,
	}
}

func (p *Ed25519TransferParameters) MarshalJSON() ([]byte, error) {
	params := Ed25519TransferParametersJSON{
		TransferParametersJSON: p.base().CreateTransferParametersJSON(),
		OwnerPublicKey:         "0x" + hex.EncodeToString(p.OwnerPublicKey[:]),
		OwnerSignature:         "0x" + hex.EncodeToString(p.OwnerSignature[:]),
		MessageHashLow:         common.FeHex(p.MessageHashLow),
		MessageHashHigh:        common.FeHex(p.MessageHashHigh),
	}
	params.CircuitType = common.TransferEd25519RingCircuitType
	return json.Marshal(params)
}

func (p *Ed25519TransferParameters) UnmarshalJSON(data []byte) error {
	var params Ed25519TransferParametersJSON
	if err := json.Unmarshal(data, &params); err != nil {
		return err
	}
	if params.CircuitType != common.TransferEd25519RingCircuitType {
		return fmt.Errorf("invalid Ed25519 transfer circuit type %q", params.CircuitType)
	}
	if len(params.PublishedOutputOwnerPkHashes) != 0 {
		return fmt.Errorf("spp: the Ed25519 ring rail publishes no output owner")
	}
	var base TransferParameters
	if err := base.UpdateWithJSON(params.TransferParametersJSON); err != nil {
		return err
	}
	*p = Ed25519TransferParameters{
		NInputs:          base.NInputs,
		NOutputs:         base.NOutputs,
		Inputs:           base.Inputs,
		Outputs:          base.Outputs,
		TreeSlots:        base.TreeSlots,
		OutputTreeID:     base.OutputTreeID,
		ExternalDataHash: base.ExternalDataHash,
		PrivateTxHash:    base.PrivateTxHash,
		BlindingSeed:     base.BlindingSeed,
		PublicAssets:     base.PublicAssets,
		PublicAmounts:    base.PublicAmounts,
		RingProgramID:    base.RingProgramID,
		SignerPkHashes:   base.SignerPkHashes,
		InputFlags:       base.InputFlags,
		Cache:            base.Cache,
		PublicInputHash:  base.PublicInputHash,
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
	p.MessageHashHigh, err = common.FeFromHex(params.MessageHashHigh)
	return err
}

// exactBytes decodes a 0x-prefixed hex string of exactly len(out) bytes.
func exactBytes(out []byte, encoded string) error {
	decoded, err := hex.DecodeString(strings.TrimPrefix(encoded, "0x"))
	if err != nil {
		return err
	}
	if len(decoded) != len(out) {
		return fmt.Errorf("got %d bytes, want %d", len(decoded), len(out))
	}
	copy(out, decoded)
	return nil
}

func (p *Ed25519TransferParameters) ValidateShape() error {
	return p.base().ValidateShape()
}

func (p *Ed25519TransferParameters) CreateWitness() (frontend.Circuit, error) {
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
	signerPkHashes := make([]frontend.Variable, len(p.SignerPkHashes))
	for i := range p.SignerPkHashes {
		signerPkHashes[i] = p.SignerPkHashes[i]
	}
	outputOwnerPkHashes := make([]frontend.Variable, len(p.Outputs))
	outputNullifierPks := make([]frontend.Variable, len(p.Outputs))
	for i, out := range p.Outputs {
		outputOwnerPkHashes[i] = orZero(out.OwnerPkHash)
		outputNullifierPks[i] = orZero(out.NullifierPk)
	}
	circuit := &customring.CustomRingEd25519Circuit{
		CachedInputs: p.Cache.circuitInputs(int(p.NInputs)),
		Shape:        shape,
		Public: customring.CustomRingEd25519Public{
			Nullifiers:       core.nullifiers,
			OutputHashes:     core.outputHashes,
			TreeSlots:        core.treeSlots,
			OutputTreeID:     p.OutputTreeID,
			PrivateTxHash:    p.PrivateTxHash,
			MessageHashLow:   p.MessageHashLow,
			MessageHashHigh:  p.MessageHashHigh,
			ExternalDataHash: p.ExternalDataHash,
			PublicAssets:     core.publicAssets,
			PublicAmounts:    core.publicAmounts,
			RingProgramID:    p.RingProgramID,
			InputFlags:       p.InputFlags,
			SignerPkHashes:   signerPkHashes,
			PublicInputHash:  p.PublicInputHash,
		},
		Private: customring.CustomRingEd25519Private{
			Inputs:              core.inputs,
			InputOwnerPkHashes:  core.inputOwnerPkHashes,
			Outputs:             core.outputs,
			OutputOwnerPkHashes: outputOwnerPkHashes,
			OutputNullifierPks:  outputNullifierPks,
			BlindingSeed:        p.BlindingSeed,
		},
	}
	for i, b := range p.OwnerPublicKey {
		circuit.Private.OwnerPublicKey[i] = b
	}
	for i, b := range p.OwnerSignature {
		circuit.Private.OwnerSignature[i] = b
	}
	return circuit, nil
}

func R1CSEd25519Transfer(nInputs uint32, nOutputs uint32) (constraint.ConstraintSystem, error) {
	circuit, err := customring.NewCustomRingEd25519Circuit(
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

func SetupEd25519Transfer(nInputs uint32, nOutputs uint32) (*common.TransferProofSystem, error) {
	if !(common.ProofShape{Circuit: common.TransferEd25519RingCircuitType, Inputs: nInputs, Outputs: nOutputs}).Supported() {
		return nil, fmt.Errorf("unsupported Ed25519 ring shape %dx%d", nInputs, nOutputs)
	}
	ccs, err := R1CSEd25519Transfer(nInputs, nOutputs)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.TransferProofSystem{
		CircuitType:      common.TransferEd25519RingCircuitType,
		NInputs:          nInputs,
		NOutputs:         nOutputs,
		RequiresP256:     true,
		Confidential:     true,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}

func (request Ed25519Proof) Prove() (*common.Proof, error) {
	ps, params := request.System, request.Parameters
	proof, err := request.Prover.Run(ps.ConstraintSystem, ps.ProvingKey, func() (frontend.Circuit, error) {
		if err := params.ValidateShape(); err != nil {
			return nil, err
		}
		assignment, err := params.CreateWitness()
		if err != nil {
			return nil, fmt.Errorf("create Ed25519 transfer witness: %w", err)
		}
		return assignment, nil
	})
	if err != nil {
		return nil, err
	}
	return &common.Proof{Proof: proof, ProvingKeySha256: ps.ProvingKeySha256}, nil
}
