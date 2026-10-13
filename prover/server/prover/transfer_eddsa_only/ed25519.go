package transfereddsaonly

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"zolana/prover/prover/backend"

	customring "zolana/prover/circuits/spp_transaction/custom"
	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"
	"zolana/prover/prover/timing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type Ed25519Proof struct {
	System     *common.TransferProofSystem
	Parameters *Ed25519TransferParameters
	Timing     *timing.Trace
}

// Ed25519TransferParameters is the flat witness for CustomRingEd25519Circuit.
type Ed25519TransferParameters struct {
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

	// Ed25519PublicKey is the compressed Edwards y encoding of the shared owner
	// key; Ed25519Signature is R || S over the 32-byte SPP signing digest.
	Ed25519PublicKey [32]byte
	Ed25519Signature [64]byte
	// The signing digest as two big-endian 128-bit halves: High is bytes 0..16.
	Ed25519MessageHashLow     *big.Int
	Ed25519MessageHashHigh    *big.Int
	DefaultEd25519OwnerPkHash *big.Int

	PublicAssets                 []*big.Int
	PublicAmounts                []*big.Int
	RingProgramID                *big.Int
	SignerPkHashes               []*big.Int
	InputFlags                   *big.Int
	PublishedOutputOwnerPkHashes []*big.Int

	Cache CacheSelectionParams

	PublicInputHash *big.Int
}

type Ed25519TransferParametersJSON struct {
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
	Ed25519PublicKey             string                      `json:"ed25519PublicKey"`
	Ed25519Signature             string                      `json:"ed25519Signature"`
	Ed25519MessageHashLow        string                      `json:"ed25519MessageHashLow"`
	Ed25519MessageHashHigh       string                      `json:"ed25519MessageHashHigh"`
	DefaultEd25519OwnerPkHash    string                      `json:"defaultEd25519OwnerPkHash"`
	PublicAssets                 []string                    `json:"publicAssets"`
	PublicAmounts                []string                    `json:"publicAmounts"`
	RingProgramID                string                      `json:"ringProgramId"`
	SignerPkHashes               []string                    `json:"signerPkHashes"`
	InputFlags                   string                      `json:"inputFlags"`
	PublishedOutputOwnerPkHashes []string                    `json:"publishedOutputOwnerPkHashes"`
	CacheSelectionJSON
	PublicInputHash string `json:"publicInputHash"`
}

func (p *Ed25519TransferParameters) MarshalJSON() ([]byte, error) {
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
		InputFlags:                   p.InputFlags,
		PublishedOutputOwnerPkHashes: p.PublishedOutputOwnerPkHashes,
		Variant:                      RingVariant,
		PublicInputHash:              p.PublicInputHash,
	}).CreateTransferParametersJSON()
	return json.Marshal(Ed25519TransferParametersJSON{
		CircuitType:                  common.TransferP256RingCircuitType,
		NInputs:                      base.NInputs,
		NOutputs:                     base.NOutputs,
		Inputs:                       base.Inputs,
		Outputs:                      base.Outputs,
		TreeSlots:                    base.TreeSlots,
		OutputTreeID:                 base.OutputTreeID,
		ExternalDataHash:             base.ExternalDataHash,
		PrivateTxHash:                base.PrivateTxHash,
		BlindingSeed:                 base.BlindingSeed,
		Ed25519PublicKey:             bytesHex(p.Ed25519PublicKey[:]),
		Ed25519Signature:             bytesHex(p.Ed25519Signature[:]),
		Ed25519MessageHashLow:        common.FeHex(p.Ed25519MessageHashLow),
		Ed25519MessageHashHigh:       common.FeHex(p.Ed25519MessageHashHigh),
		DefaultEd25519OwnerPkHash:    common.FeHex(p.DefaultEd25519OwnerPkHash),
		PublicAssets:                 base.PublicAssets,
		PublicAmounts:                base.PublicAmounts,
		RingProgramID:                base.RingProgramID,
		SignerPkHashes:               base.SignerPkHashes,
		InputFlags:                   base.InputFlags,
		PublishedOutputOwnerPkHashes: base.PublishedOutputOwnerPkHashes,
		CacheSelectionJSON:           base.CacheSelectionJSON,
		PublicInputHash:              base.PublicInputHash,
	})
}

func (p *Ed25519TransferParameters) UnmarshalJSON(data []byte) error {
	var params Ed25519TransferParametersJSON
	if err := json.Unmarshal(data, &params); err != nil {
		return err
	}
	if params.CircuitType != common.TransferP256RingCircuitType {
		return fmt.Errorf("invalid Ed25519 transfer circuit type %q", params.CircuitType)
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
	p.InputFlags = base.InputFlags
	p.PublishedOutputOwnerPkHashes = base.PublishedOutputOwnerPkHashes
	p.Cache = base.Cache
	p.PublicInputHash = base.PublicInputHash

	if err := bytesFromHex(p.Ed25519PublicKey[:], params.Ed25519PublicKey, "ed25519PublicKey"); err != nil {
		return err
	}
	if err := bytesFromHex(p.Ed25519Signature[:], params.Ed25519Signature, "ed25519Signature"); err != nil {
		return err
	}
	var err error
	for target, encoded := range map[**big.Int]string{
		&p.Ed25519MessageHashLow:     params.Ed25519MessageHashLow,
		&p.Ed25519MessageHashHigh:    params.Ed25519MessageHashHigh,
		&p.DefaultEd25519OwnerPkHash: params.DefaultEd25519OwnerPkHash,
	} {
		if *target, err = common.FeFromHex(encoded); err != nil {
			return err
		}
	}
	return nil
}

func (p *Ed25519TransferParameters) ValidateShape() error {
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
	var ed25519PublicKey [32]frontend.Variable
	for i, b := range p.Ed25519PublicKey {
		ed25519PublicKey[i] = b
	}
	var ed25519Signature [64]frontend.Variable
	for i, b := range p.Ed25519Signature {
		ed25519Signature[i] = b
	}
	return &customring.CustomRingEd25519Circuit{
		CachedInputs: p.Cache.circuitInputs(int(p.NInputs)),
		Shape:        txcircuit.Shape{NInputs: int(p.NInputs), NOutputs: int(p.NOutputs)},
		Public: customring.CustomRingEd25519Public{
			Nullifiers:                   core.nullifiers,
			OutputHashes:                 core.outputHashes,
			TreeSlots:                    core.treeSlots,
			OutputTreeID:                 p.OutputTreeID,
			PrivateTxHash:                p.PrivateTxHash,
			Ed25519MessageHashLow:        p.Ed25519MessageHashLow,
			Ed25519MessageHashHigh:       p.Ed25519MessageHashHigh,
			DefaultEd25519OwnerPkHash:    p.DefaultEd25519OwnerPkHash,
			ExternalDataHash:             p.ExternalDataHash,
			PublicAssets:                 core.publicAssets,
			PublicAmounts:                core.publicAmounts,
			RingProgramID:                p.RingProgramID,
			InputFlags:                   p.InputFlags,
			SignerPkHashes:               signerPkHashes,
			PublishedOutputOwnerPkHashes: publishedOutputOwnerPkHashes,
			PublicInputHash:              p.PublicInputHash,
		},
		Private: customring.CustomRingEd25519Private{
			Inputs:              core.inputs,
			InputOwnerPkHashes:  core.inputOwnerPkHashes,
			Outputs:             core.outputs,
			OutputOwnerPkHashes: outputOwnerPkHashes,
			OutputNullifierPks:  outputNullifierPks,
			BlindingSeed:        p.BlindingSeed,
			Ed25519PublicKey:    ed25519PublicKey,
			Ed25519Signature:    ed25519Signature,
		},
	}, nil
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
	ccs, err := R1CSEd25519Transfer(nInputs, nOutputs)
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

func (request Ed25519Proof) Prove() (*common.Proof, error) {
	ps, params := request.System, request.Parameters
	proof, err := backend.ProveAssignment(request.Timing, ps.ConstraintSystem, ps.ProvingKey, func() (frontend.Circuit, error) {
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

func bytesHex(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

// bytesFromHex accepts only the canonical form bytesHex writes: 0x-prefixed
// lowercase hex of exactly len(dst) bytes.
func bytesFromHex(dst []byte, s string, name string) error {
	if len(s) != 2+2*len(dst) || !strings.HasPrefix(s, "0x") || strings.ToLower(s) != s {
		return fmt.Errorf("spp: %s is not canonical %d-byte hex", name, len(dst))
	}
	decoded, err := hex.DecodeString(s[2:])
	if err != nil {
		return fmt.Errorf("spp: %s: %w", name, err)
	}
	copy(dst, decoded)
	return nil
}
