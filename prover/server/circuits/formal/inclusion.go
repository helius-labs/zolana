// Package formal defines the standalone inclusion and non-inclusion circuits
// extracted to Lean by the formal verification pipeline
// (prover/server/formal-verification). They compose exactly the gadgets the
// live SPP circuits use — state-tree inclusion (spp_transaction/spp_merge
// constrainInput) and nullifier-tree non-inclusion (low-leaf bracketing with
// full-field ordering) — so the Lean theorems about these circuits cover the
// shared gadget semantics. The circuits are not part of any proving system;
// they exist only for extraction.
package formal

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
)

// InclusionCircuit proves each Leaves[i] is a leaf of the state tree with
// root Roots[i]. The public input hash chains the column hash chains, the
// same compression the SPP transaction circuit applies to its public columns.
type InclusionCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	Roots          []frontend.Variable   `gnark:",secret"`
	Leaves         []frontend.Variable   `gnark:",secret"`
	InPathIndices  []frontend.Variable   `gnark:",secret"`
	InPathElements [][]frontend.Variable `gnark:",secret"`

	NumberOfUtxos uint32
	Height        uint32
}

func (circuit *InclusionCircuit) Define(api frontend.API) error {
	publicInputsHash := gadget.HashChain(api, []frontend.Variable{
		gadget.HashChain(api, circuit.Roots),
		gadget.HashChain(api, circuit.Leaves),
	})
	api.AssertIsEqual(circuit.PublicInputHash, publicInputsHash)

	abstractor.Call1(api, gadget.InclusionProof{
		Roots:          circuit.Roots,
		Leaves:         circuit.Leaves,
		InPathIndices:  circuit.InPathIndices,
		InPathElements: circuit.InPathElements,

		NumberOfCompressedAccounts: circuit.NumberOfUtxos,
		Height:                     circuit.Height,
	})
	return nil
}
