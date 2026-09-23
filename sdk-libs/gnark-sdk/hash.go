package gnarksdk

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction/shared"
)

// MaxPoseidonInputs is the widest Poseidon light_hasher computes, so a wider
// in-circuit hash could never be recomputed by a program or client.
const MaxPoseidonInputs = 12

// Poseidon is light_hasher's BN254 Poseidon of 1 to MaxPoseidonInputs values.
// An unsupported field or arity panics, which frontend.Compile reports as a
// compile error.
func Poseidon(api frontend.API, inputs ...frontend.Variable) frontend.Variable {
	if api.Compiler().Field().Cmp(ecc.BN254.ScalarField()) != 0 {
		panic("gnarksdk: Poseidon requires the BN254 scalar field")
	}
	if len(inputs) < 1 || len(inputs) > MaxPoseidonInputs {
		panic(fmt.Sprintf("gnarksdk: Poseidon takes 1 to %d inputs, got %d", MaxPoseidonInputs, len(inputs)))
	}
	return gadget.PoseidonHash(api, inputs)
}

// HashBytes is zolana_hasher's hash_bytes of a fixed-length byte string, one
// variable per byte: 31-byte big-endian chunks folded left to right.
func HashBytes(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	return gadget.HashBytes(api, bytes)
}

// PrivateTxHash is the private transaction hash of a transaction that creates
// no address, so every address nullifier is 0. inputs and outputs are UTXO
// hashes in transaction slot order, with 0 for a padding slot.
func PrivateTxHash(api frontend.API, inputs, outputs []frontend.Variable, externalDataHash, privateTxBlinding frontend.Variable) frontend.Variable {
	addressNullifiers := make([]frontend.Variable, len(inputs))
	for i := range addressNullifiers {
		addressNullifiers[i] = 0
	}
	return spp.PrivateTxHashCircuit(api, inputs, outputs, addressNullifiers, externalDataHash, privateTxBlinding)
}
