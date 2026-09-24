package read

import (
	"github.com/consensys/gnark/frontend"

	"zolana/gnarksdk"
	"zolana/prover/circuits/gadget"
)

// Circuit proves a compressed account UTXO is unspent: its hash is a leaf of
// the state tree at UtxoRoot and its nullifier is absent from the nullifier
// tree at NullifierRoot. The program recomputes the UTXO hash and nullifier
// from the plaintext state and reads both roots from the tree account, so the
// circuit takes them as given.
type Circuit struct {
	Public PublicInputs
	Read   gnarksdk.UtxoRead
}

func (c *Circuit) Define(api frontend.API) error {
	c.Public.Check(api)
	c.Read.Assert(api, c.Public.UtxoHash, c.Public.UtxoRoot, c.Public.Nullifier, c.Public.NullifierRoot)
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
