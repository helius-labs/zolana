package transfereddsa

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

type AnonymousEddsaProof struct {
	System     *common.TransferProofSystem
	Parameters *AnonymousEddsaTransferParameters
	Prover     common.Prover
}

// AnonymousEddsaTransferParameters is the flat witness for CustomRingAnonymousEddsaCircuit.
type AnonymousEddsaTransferParameters struct {
	NInputs  uint32
	NOutputs uint32

	Inputs  []InputParams
	Outputs []OutputParams
	// TreeSlots are the shared.InputTrees public tree slots inputs may be spent
	// from; unused slots are all zero. Each input names its own slot privately.
	TreeSlots []common.TreeSlotParams
	// OutputTreeID is the raw u16 id of the tree every output is appended to.
	OutputTreeID *big.Int

	ExternalDataHash *big.Int
	PrivateTxHash    *big.Int
	// BlindingSeed is the transaction's private random root seed; the circuit
	// derives the output blinding seed, every output blinding, and the private
	// tx blinding from it and the first nullifier.
	BlindingSeed *big.Int

	// The first hidden owner's key and signature over the message.
	OwnerPublicKey [32]byte
	OwnerSignature [64]byte
	// NHiddenOwners selects a circuit with this many hidden owners. Zero is
	// the protocol's single owner. Owners after the first carry their keys and
	// signatures here, and InputHiddenOwners names each input's owner (0 for
	// a non-hidden input); all three are empty for a single owner.
	NHiddenOwners             uint32
	AdditionalOwnerPublicKeys [][32]byte
	AdditionalOwnerSignatures [][64]byte
	InputHiddenOwners         []uint32
	MessageHashLow            *big.Int
	MessageHashHigh           *big.Int
	DefaultOwnerPkHash        *big.Int

	PublicAssets   []*big.Int
	PublicAmounts  []*big.Int
	RingProgramID  *big.Int
	SignerPkHashes []*big.Int
	// SignerWidth selects a circuit whose public signer vector has this many
	// slots. Zero is the protocol width.
	SignerWidth                  uint32
	InputFlags                   *big.Int
	PublishedOutputOwnerPkHashes []*big.Int

	Cache CacheSelectionParams

	PublicInputHash *big.Int
}

type AnonymousEddsaTransferParametersJSON struct {
	CircuitType                  common.CircuitType          `json:"circuitType"`
	NInputs                      uint32                      `json:"nInputs"`
	NOutputs                     uint32                      `json:"nOutputs"`
	Inputs                       []InputParamsJSON           `json:"inputs"`
	Outputs                      []OutputParamsJSON          `json:"outputs"`
	TreeSlots                    []common.TreeSlotParamsJSON `json:"treeSlots"`
	OutputTreeID                 string                      `json:"outputTreeId"`
	ExternalDataHash             string                      `json:"externalDataHash"`
	PrivateTxHash                string                      `json:"privateTxHash"`
	BlindingSeed                 string                      `json:"blindingSeed"`
	OwnerPublicKey               string                      `json:"ownerPublicKey"`
	OwnerSignature               string                      `json:"ownerSignature"`
	NHiddenOwners                uint32                      `json:"nHiddenOwners,omitempty"`
	AdditionalOwnerPublicKeys    []string                    `json:"additionalOwnerPublicKeys,omitempty"`
	AdditionalOwnerSignatures    []string                    `json:"additionalOwnerSignatures,omitempty"`
	InputHiddenOwners            []uint32                    `json:"inputHiddenOwners,omitempty"`
	MessageHashLow               string                      `json:"messageHashLow"`
	MessageHashHigh              string                      `json:"messageHashHigh"`
	DefaultOwnerPkHash           string                      `json:"defaultOwnerPkHash"`
	PublicAssets                 []string                    `json:"publicAssets"`
	PublicAmounts                []string                    `json:"publicAmounts"`
	RingProgramID                string                      `json:"ringProgramId"`
	SignerPkHashes               []string                    `json:"signerPkHashes"`
	SignerWidth                  uint32                      `json:"signerWidth,omitempty"`
	InputFlags                   string                      `json:"inputFlags"`
	PublishedOutputOwnerPkHashes []string                    `json:"publishedOutputOwnerPkHashes"`
	CacheSelectionJSON
	PublicInputHash string `json:"publicInputHash"`
}

func (p *AnonymousEddsaTransferParameters) MarshalJSON() ([]byte, error) {
	base := (&TransferParameters{
		NInputs:                      p.NInputs,
		NOutputs:                     p.NOutputs,
		Inputs:                       p.Inputs,
		Outputs:                      p.Outputs,
		TreeSlots:                    p.TreeSlots,
		OutputTreeID:                 p.OutputTreeID,
		ExternalDataHash:             p.ExternalDataHash,
		PrivateTxHash:                p.PrivateTxHash,
		BlindingSeed:                 p.BlindingSeed,
		PublicAssets:                 p.PublicAssets,
		PublicAmounts:                p.PublicAmounts,
		RingProgramID:                p.RingProgramID,
		SignerPkHashes:               p.SignerPkHashes,
		SignerWidth:                  p.SignerWidth,
		InputFlags:                   p.InputFlags,
		PublishedOutputOwnerPkHashes: p.PublishedOutputOwnerPkHashes,
		Cache:                        p.Cache,
		Variant:                      RingVariant,
		PublicInputHash:              p.PublicInputHash,
	}).CreateTransferParametersJSON()
	return json.Marshal(AnonymousEddsaTransferParametersJSON{
		CircuitType:                  common.TransferAnonymousRingEddsaCircuitType,
		NInputs:                      base.NInputs,
		NOutputs:                     base.NOutputs,
		Inputs:                       base.Inputs,
		Outputs:                      base.Outputs,
		TreeSlots:                    base.TreeSlots,
		OutputTreeID:                 base.OutputTreeID,
		ExternalDataHash:             base.ExternalDataHash,
		PrivateTxHash:                base.PrivateTxHash,
		BlindingSeed:                 base.BlindingSeed,
		OwnerPublicKey:               "0x" + hex.EncodeToString(p.OwnerPublicKey[:]),
		OwnerSignature:               "0x" + hex.EncodeToString(p.OwnerSignature[:]),
		NHiddenOwners:                p.NHiddenOwners,
		AdditionalOwnerPublicKeys:    hexKeys(p.AdditionalOwnerPublicKeys),
		AdditionalOwnerSignatures:    hexSignatures(p.AdditionalOwnerSignatures),
		InputHiddenOwners:            p.InputHiddenOwners,
		MessageHashLow:               common.FeHex(p.MessageHashLow),
		MessageHashHigh:              common.FeHex(p.MessageHashHigh),
		DefaultOwnerPkHash:           common.FeHex(p.DefaultOwnerPkHash),
		PublicAssets:                 base.PublicAssets,
		PublicAmounts:                base.PublicAmounts,
		RingProgramID:                base.RingProgramID,
		SignerPkHashes:               base.SignerPkHashes,
		SignerWidth:                  base.SignerWidth,
		InputFlags:                   base.InputFlags,
		PublishedOutputOwnerPkHashes: base.PublishedOutputOwnerPkHashes,
		CacheSelectionJSON:           base.CacheSelectionJSON,
		PublicInputHash:              base.PublicInputHash,
	})
}

func (p *AnonymousEddsaTransferParameters) UnmarshalJSON(data []byte) error {
	var params AnonymousEddsaTransferParametersJSON
	if err := json.Unmarshal(data, &params); err != nil {
		return err
	}
	if params.CircuitType != common.TransferAnonymousRingEddsaCircuitType {
		return fmt.Errorf("invalid EdDSA transfer circuit type %q", params.CircuitType)
	}
	base := TransferParameters{}
	if err := base.UpdateWithJSON(TransferParametersJSON{
		CircuitType:                  common.TransferRingCircuitType,
		NInputs:                      params.NInputs,
		NOutputs:                     params.NOutputs,
		Inputs:                       params.Inputs,
		Outputs:                      params.Outputs,
		TreeSlots:                    params.TreeSlots,
		OutputTreeID:                 params.OutputTreeID,
		ExternalDataHash:             params.ExternalDataHash,
		PrivateTxHash:                params.PrivateTxHash,
		BlindingSeed:                 params.BlindingSeed,
		PublicAssets:                 params.PublicAssets,
		PublicAmounts:                params.PublicAmounts,
		RingProgramID:                params.RingProgramID,
		SignerPkHashes:               params.SignerPkHashes,
		SignerWidth:                  params.SignerWidth,
		InputFlags:                   params.InputFlags,
		PublishedOutputOwnerPkHashes: params.PublishedOutputOwnerPkHashes,
		CacheSelectionJSON:           params.CacheSelectionJSON,
		PublicInputHash:              params.PublicInputHash,
	}); err != nil {
		return err
	}
	p.NInputs = base.NInputs
	p.NOutputs = base.NOutputs
	p.Inputs = base.Inputs
	p.Outputs = base.Outputs
	p.TreeSlots = base.TreeSlots
	p.OutputTreeID = base.OutputTreeID
	p.ExternalDataHash = base.ExternalDataHash
	p.PrivateTxHash = base.PrivateTxHash
	p.BlindingSeed = base.BlindingSeed
	p.PublicAssets = base.PublicAssets
	p.PublicAmounts = base.PublicAmounts
	p.RingProgramID = base.RingProgramID
	p.SignerPkHashes = base.SignerPkHashes
	p.SignerWidth = base.SignerWidth
	p.InputFlags = base.InputFlags
	p.PublishedOutputOwnerPkHashes = base.PublishedOutputOwnerPkHashes
	p.Cache = base.Cache
	p.PublicInputHash = base.PublicInputHash

	if err := exactBytes(p.OwnerPublicKey[:], params.OwnerPublicKey); err != nil {
		return fmt.Errorf("ownerPublicKey: %w", err)
	}
	if err := exactBytes(p.OwnerSignature[:], params.OwnerSignature); err != nil {
		return fmt.Errorf("ownerSignature: %w", err)
	}
	p.NHiddenOwners = params.NHiddenOwners
	p.AdditionalOwnerPublicKeys = make([][32]byte, len(params.AdditionalOwnerPublicKeys))
	for j, encoded := range params.AdditionalOwnerPublicKeys {
		if err := exactBytes(p.AdditionalOwnerPublicKeys[j][:], encoded); err != nil {
			return fmt.Errorf("additionalOwnerPublicKeys[%d]: %w", j, err)
		}
	}
	p.AdditionalOwnerSignatures = make([][64]byte, len(params.AdditionalOwnerSignatures))
	for j, encoded := range params.AdditionalOwnerSignatures {
		if err := exactBytes(p.AdditionalOwnerSignatures[j][:], encoded); err != nil {
			return fmt.Errorf("additionalOwnerSignatures[%d]: %w", j, err)
		}
	}
	p.InputHiddenOwners = params.InputHiddenOwners
	var err error
	for target, encoded := range map[**big.Int]string{
		&p.MessageHashLow:     params.MessageHashLow,
		&p.MessageHashHigh:    params.MessageHashHigh,
		&p.DefaultOwnerPkHash: params.DefaultOwnerPkHash,
	} {
		if *target, err = common.FeFromHex(encoded); err != nil {
			return err
		}
	}
	return nil
}

// hexKeys encodes public keys as 0x-prefixed hex, nil when there are none.
func hexKeys(keys [][32]byte) []string {
	var out []string
	for _, key := range keys {
		out = append(out, "0x"+hex.EncodeToString(key[:]))
	}
	return out
}

// hexSignatures encodes signatures as 0x-prefixed hex, nil when there are none.
func hexSignatures(signatures [][64]byte) []string {
	var out []string
	for _, signature := range signatures {
		out = append(out, "0x"+hex.EncodeToString(signature[:]))
	}
	return out
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

// ProofShape is the circuit and key the parameters prove with.
func (p *AnonymousEddsaTransferParameters) ProofShape() common.ProofShape {
	return normalizedProofShape(common.ProofShape{
		Circuit:      common.TransferAnonymousRingEddsaCircuitType,
		Inputs:       p.NInputs,
		Outputs:      p.NOutputs,
		SignerWidth:  p.SignerWidth,
		HiddenOwners: p.NHiddenOwners,
	})
}

// validateHiddenOwners checks the hidden owner wires against the shape. The
// circuit would only fail them as an opaque proving error.
func (p *AnonymousEddsaTransferParameters) validateHiddenOwners() error {
	shape := p.ProofShape()
	if !shape.IsProtocol() && !shape.Supported() {
		return fmt.Errorf("unsupported transfer shape %s", shape)
	}
	owners := CircuitShape(shape).NHiddenOwners
	if len(p.AdditionalOwnerPublicKeys) != owners-1 || len(p.AdditionalOwnerSignatures) != owners-1 {
		return fmt.Errorf(
			"spp: %d hidden owners need %d additional keys and signatures, got %d and %d",
			owners, owners-1, len(p.AdditionalOwnerPublicKeys), len(p.AdditionalOwnerSignatures),
		)
	}
	wantIndices := 0
	if owners > 1 {
		wantIndices = int(p.NInputs)
	}
	if len(p.InputHiddenOwners) != wantIndices {
		return fmt.Errorf("spp: input hidden owner count mismatch: got %d want %d", len(p.InputHiddenOwners), wantIndices)
	}
	for i, owner := range p.InputHiddenOwners {
		if int(owner) >= owners {
			return fmt.Errorf("spp: input %d names hidden owner %d of %d", i, owner, owners)
		}
	}
	return nil
}

func (p *AnonymousEddsaTransferParameters) ValidateShape() error {
	if err := p.validateHiddenOwners(); err != nil {
		return err
	}
	return (&TransferParameters{
		NInputs:      p.NInputs,
		NOutputs:     p.NOutputs,
		Inputs:       p.Inputs,
		Outputs:      p.Outputs,
		TreeSlots:    p.TreeSlots,
		OutputTreeID: p.OutputTreeID,
		InputFlags:   p.InputFlags,
		Cache:        p.Cache,
	}).ValidateShape()
}

func (p *AnonymousEddsaTransferParameters) CreateWitness() (frontend.Circuit, error) {
	core, err := buildWitnessCore(p.Inputs, p.Outputs, p.TreeSlots, p.PublicAssets, p.PublicAmounts)
	if err != nil {
		return nil, err
	}
	shape := CircuitShape(p.ProofShape())
	if len(p.SignerPkHashes) != shape.SignerWidth {
		return nil, fmt.Errorf(
			"spp: signer pk hash count mismatch: got %d want %d",
			len(p.SignerPkHashes),
			shape.SignerWidth,
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
	circuit := &customring.CustomRingAnonymousEddsaCircuit{
		CachedInputs: p.Cache.circuitInputs(int(p.NInputs)),
		Shape:        shape,
		Public: customring.CustomRingAnonymousEddsaPublic{
			Nullifiers:                   core.nullifiers,
			OutputHashes:                 core.outputHashes,
			TreeSlots:                    core.treeSlots,
			OutputTreeID:                 p.OutputTreeID,
			PrivateTxHash:                p.PrivateTxHash,
			MessageHashLow:               p.MessageHashLow,
			MessageHashHigh:              p.MessageHashHigh,
			DefaultOwnerPkHash:           p.DefaultOwnerPkHash,
			ExternalDataHash:             p.ExternalDataHash,
			PublicAssets:                 core.publicAssets,
			PublicAmounts:                core.publicAmounts,
			RingProgramID:                p.RingProgramID,
			InputFlags:                   p.InputFlags,
			SignerPkHashes:               signerPkHashes,
			PublishedOutputOwnerPkHashes: publishedOutputOwnerPkHashes,
			PublicInputHash:              p.PublicInputHash,
		},
		Private: customring.CustomRingAnonymousEddsaPrivate{
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
	if shape.NHiddenOwners > 1 {
		circuit.Private.AdditionalOwnerPublicKeys = make([][32]frontend.Variable, len(p.AdditionalOwnerPublicKeys))
		for j, key := range p.AdditionalOwnerPublicKeys {
			for i, b := range key {
				circuit.Private.AdditionalOwnerPublicKeys[j][i] = b
			}
		}
		circuit.Private.AdditionalOwnerSignatures = make([][64]frontend.Variable, len(p.AdditionalOwnerSignatures))
		for j, signature := range p.AdditionalOwnerSignatures {
			for i, b := range signature {
				circuit.Private.AdditionalOwnerSignatures[j][i] = b
			}
		}
		circuit.Private.InputHiddenOwners = make([]frontend.Variable, len(p.InputHiddenOwners))
		for i, owner := range p.InputHiddenOwners {
			circuit.Private.InputHiddenOwners[i] = owner
		}
	}
	return circuit, nil
}

func R1CSAnonymousEddsaTransfer(nInputs uint32, nOutputs uint32) (constraint.ConstraintSystem, error) {
	circuit, err := customring.NewCustomRingAnonymousEddsaCircuit(
		txcircuit.NewShape(int(nInputs), int(nOutputs)),
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

func SetupAnonymousEddsaTransfer(nInputs uint32, nOutputs uint32) (*common.TransferProofSystem, error) {
	ccs, err := R1CSAnonymousEddsaTransfer(nInputs, nOutputs)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.TransferProofSystem{
		CircuitType:      common.TransferAnonymousRingEddsaCircuitType,
		NInputs:          nInputs,
		NOutputs:         nOutputs,
		HasCommitment:    true,
		Confidential:     true,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}

func (request AnonymousEddsaProof) Prove() (*common.Proof, error) {
	ps, params := request.System, request.Parameters
	if err := checkSystem(ps, params.ProofShape()); err != nil {
		return nil, err
	}
	proof, err := request.Prover.Run(ps.ConstraintSystem, ps.ProvingKey, func() (frontend.Circuit, error) {
		if err := params.ValidateShape(); err != nil {
			return nil, err
		}
		assignment, err := params.CreateWitness()
		if err != nil {
			return nil, fmt.Errorf("create EdDSA transfer witness: %w", err)
		}
		return assignment, nil
	})
	if err != nil {
		return nil, err
	}
	return &common.Proof{Proof: proof, ProvingKeySha256: ps.ProvingKeySha256}, nil
}
