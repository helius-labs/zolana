// Package registry proves that a UTXO owner's nullifier key is escrowed in the
// ring's key registry.
package registry

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
)

const Height = 40

// ZeroNullifierPk is Poseidon(0), the nullifier public key of the zero secret.
var ZeroNullifierPk, _ = new(big.Int).SetString(
	"2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c", 16)

// KeyOpening opens the leaf Poseidon(member, next, Poseidon(nullifierPk, ctHash)).
type KeyOpening struct {
	Next   frontend.Variable
	CtHash frontend.Variable
	Index  frontend.Variable
	Path   [Height]frontend.Variable
}

// AssertMode requires a boolean escrow flag and a zero root when it is off.
func AssertMode(api frontend.API, escrow, root frontend.Variable) {
	api.AssertIsBoolean(escrow)
	api.AssertIsEqual(api.Mul(root, api.Sub(1, escrow)), 0)
}

// AssertEscrowed requires the zero key or a leaf under root while cond is set.
func (k KeyOpening) AssertEscrowed(api frontend.API, cond, root, ownerPkHash, nullifierPk frontend.Variable) {
	leaf := Leaf{
		Member: ownerPkHash,
		Next:   k.Next,
		Key:    gadget.PoseidonHash(api, []frontend.Variable{nullifierPk, k.CtHash}),
	}.Hash(api)
	opened := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   leaf,
		Index:  api.ToBinary(k.Index, Height),
		Path:   k.Path[:],
		Height: Height,
	})
	api.AssertIsEqual(api.Mul(cond, api.Sub(nullifierPk, ZeroNullifierPk), api.Sub(opened, root)), 0)
}
