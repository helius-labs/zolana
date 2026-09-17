// Package receipt proves nullifier receipts: batch non-inclusion of published
// nullifiers against a nullifier tree root. The witness is public data, so any
// party holding the nullifier list and indexer access can request one.
package receipt

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	circuit "zolana/prover/circuits/nullifier_receipt"
	transaction "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"
)

// SupportedNInputs are the receipt shapes a proving system exists for. A
// receipt pads to the next shape with zero slots; Count is the active count.
// 8 covers a single small merge and hermetic tests; 512 is the batch shape.
var SupportedNInputs = []uint32{8, 512}

func IsSupportedNInputs(n uint32) bool {
	for _, supported := range SupportedNInputs {
		if supported == n {
			return true
		}
	}
	return false
}

type WitnessParams struct {
	Low   *big.Int
	Next  *big.Int
	Index *big.Int
	Path  []*big.Int
}

// Parameters is the pre-computed receipt witness. Nullifiers has the shape's
// length with zero padding after the first Count entries; Witnesses is aligned.
type Parameters struct {
	TreeID          *big.Int
	Root            *big.Int
	Count           *big.Int
	Nullifiers      []*big.Int
	Witnesses       []WitnessParams
	PublicInputHash *big.Int
}

type witnessJSON struct {
	Low   string   `json:"low"`
	Next  string   `json:"next"`
	Index string   `json:"index"`
	Path  []string `json:"path"`
}

type parametersJSON struct {
	CircuitType     common.CircuitType `json:"circuitType"`
	NInputs         uint32             `json:"nInputs"`
	TreeID          string             `json:"treeId"`
	Root            string             `json:"root"`
	Count           string             `json:"count"`
	Nullifiers      []string           `json:"nullifiers"`
	Witnesses       []witnessJSON      `json:"witnesses"`
	PublicInputHash string             `json:"publicInputHash"`
}

func (p *Parameters) MarshalJSON() ([]byte, error) {
	out := parametersJSON{
		CircuitType:     common.NullifierReceiptCircuitType,
		NInputs:         uint32(len(p.Nullifiers)),
		TreeID:          common.FeHex(p.TreeID),
		Root:            common.FeHex(p.Root),
		Count:           common.FeHex(p.Count),
		Nullifiers:      common.FeHexSlice(p.Nullifiers),
		Witnesses:       make([]witnessJSON, len(p.Witnesses)),
		PublicInputHash: common.FeHex(p.PublicInputHash),
	}
	for i, w := range p.Witnesses {
		out.Witnesses[i] = witnessJSON{
			Low: common.FeHex(w.Low), Next: common.FeHex(w.Next), Index: common.FeHex(w.Index), Path: common.FeHexSlice(w.Path),
		}
	}
	return json.Marshal(out)
}

func (p *Parameters) UnmarshalJSON(data []byte) error {
	var in parametersJSON
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	if in.CircuitType != "" && in.CircuitType != common.NullifierReceiptCircuitType {
		return fmt.Errorf("receipt: unexpected circuit type %s", in.CircuitType)
	}
	var err error
	if p.TreeID, err = common.FeFromHex(in.TreeID); err != nil {
		return err
	}
	if p.Root, err = common.FeFromHex(in.Root); err != nil {
		return err
	}
	if p.Count, err = common.FeFromHex(in.Count); err != nil {
		return err
	}
	if p.Nullifiers, err = common.FeFromHexSlice(in.Nullifiers); err != nil {
		return err
	}
	if p.PublicInputHash, err = common.FeFromHex(in.PublicInputHash); err != nil {
		return err
	}
	p.Witnesses = make([]WitnessParams, len(in.Witnesses))
	for i, w := range in.Witnesses {
		if p.Witnesses[i].Low, err = common.FeFromHex(w.Low); err != nil {
			return err
		}
		if p.Witnesses[i].Next, err = common.FeFromHex(w.Next); err != nil {
			return err
		}
		if p.Witnesses[i].Index, err = common.FeFromHex(w.Index); err != nil {
			return err
		}
		if p.Witnesses[i].Path, err = common.FeFromHexSlice(w.Path); err != nil {
			return err
		}
	}
	return nil
}

// ValidateShape rejects anything that is not exactly one supported shape with
// full-height paths, before witness assignment.
func (p *Parameters) ValidateShape() error {
	n := len(p.Nullifiers)
	if !IsSupportedNInputs(uint32(n)) {
		return fmt.Errorf("receipt: unsupported shape %d, want one of %v", n, SupportedNInputs)
	}
	if len(p.Witnesses) != n {
		return fmt.Errorf("receipt: %d witnesses for %d nullifiers", len(p.Witnesses), n)
	}
	for i, w := range p.Witnesses {
		if len(w.Path) != transaction.NullifierTreeHeight {
			return fmt.Errorf("receipt: witness %d path length %d, want %d", i, len(w.Path), transaction.NullifierTreeHeight)
		}
	}
	return nil
}

func (p *Parameters) CreateWitness() (*circuit.Circuit, error) {
	if err := p.ValidateShape(); err != nil {
		return nil, err
	}
	c := circuit.New(len(p.Nullifiers))
	c.TreeID, c.Root, c.Count, c.PublicInputHash = p.TreeID, p.Root, p.Count, p.PublicInputHash
	for i := range p.Nullifiers {
		c.Nullifiers[i] = p.Nullifiers[i]
		path := make([]frontend.Variable, len(p.Witnesses[i].Path))
		for j, element := range p.Witnesses[i].Path {
			path[j] = element
		}
		c.Witnesses[i] = circuit.NonInclusion{Low: p.Witnesses[i].Low, Next: p.Witnesses[i].Next, Index: p.Witnesses[i].Index, Path: path}
	}
	return c, nil
}

func Setup(n uint32) (*common.TransferProofSystem, error) {
	if !IsSupportedNInputs(n) {
		return nil, fmt.Errorf("receipt: unsupported shape %d, want one of %v", n, SupportedNInputs)
	}
	ccs, err := circuit.Compile(int(n))
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.TransferProofSystem{CircuitType: common.NullifierReceiptCircuitType, NInputs: n,
		ProvingKey: pk, VerifyingKey: vk, ConstraintSystem: ccs}, nil
}

func Prove(ps *common.TransferProofSystem, params *Parameters) (*common.Proof, error) {
	if ps.CircuitType != common.NullifierReceiptCircuitType || int(ps.NInputs) != len(params.Nullifiers) {
		return nil, fmt.Errorf("receipt: proving system does not match request")
	}
	assignment, err := params.CreateWitness()
	if err != nil {
		return nil, err
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	if err != nil {
		return nil, err
	}
	return &common.Proof{Proof: proof}, nil
}
