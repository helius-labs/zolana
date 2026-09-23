package read

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction/shared"
)

// Circuit proves a compressed account UTXO is unspent: its hash is a leaf of
// the state tree at UtxoRoot and its nullifier is absent from the nullifier
// tree at NullifierRoot. The program recomputes the UTXO hash and nullifier
// from the plaintext state and reads both roots from the tree account, so the
// circuit takes them as given.
type Circuit struct {
	Public PublicInputs

	StatePathElements [spp.StateTreeHeight]frontend.Variable
	StatePathIndex    frontend.Variable

	NullifierLowValue        frontend.Variable
	NullifierNextValue       frontend.Variable
	NullifierLowPathElements [spp.NullifierTreeHeight]frontend.Variable
	NullifierLowPathIndex    frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	c.Public.Check(api)
	c.checkInclusion(api)
	c.checkNonInclusion(api)
	return nil
}

type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	UtxoHash      frontend.Variable
	UtxoRoot      frontend.Variable
	Nullifier     frontend.Variable
	NullifierRoot frontend.Variable
}

func (p PublicInputs) Check(api frontend.API) {
	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{
		p.UtxoHash,
		p.UtxoRoot,
		p.Nullifier,
		p.NullifierRoot,
	})
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

func (c *Circuit) checkInclusion(api frontend.API) {
	root := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   c.Public.UtxoHash,
		Index:  api.ToBinary(c.StatePathIndex, spp.StateTreeHeight),
		Path:   c.StatePathElements[:],
		Height: spp.StateTreeHeight,
	})
	api.AssertIsEqual(root, c.Public.UtxoRoot)
}

// The low leaf H(NullifierLowValue, NullifierNextValue) is in the nullifier
// tree and brackets the nullifier over full field values, so the nullifier is
// not in the tree.
func (c *Circuit) checkNonInclusion(api frontend.API) {
	lowLeafHash := gadget.IndexedLeafHash(api, c.NullifierLowValue, c.NullifierNextValue)
	root := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   lowLeafHash,
		Index:  api.ToBinary(c.NullifierLowPathIndex, spp.NullifierTreeHeight),
		Path:   c.NullifierLowPathElements[:],
		Height: spp.NullifierTreeHeight,
	})
	api.AssertIsEqual(root, c.Public.NullifierRoot)
	abstractor.CallVoid(api, spp.AssertStrictlyOrdered{
		Lo:  c.NullifierLowValue,
		Mid: c.Public.Nullifier,
		Hi:  c.NullifierNextValue,
	})
}
