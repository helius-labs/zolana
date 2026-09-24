package gadget

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

// Sha256NodeBytes is the byte width of a state tree node encoding.
const Sha256NodeBytes = 32

func init() {
	solver.RegisterHint(bytesBEHint)
}

// Sha256MerkleRoot recomputes a state tree root where every node is
// sha256(left || right) over 32-byte big-endian encodings, with the first
// digest byte zeroed so the node fits the BN254 scalar field.
//
// The byte-level SHA-256 gadget uses log-derivative lookup tables and range
// checks, which gnark backs with a single BSB22 commitment over private wires.
//
// The leaf is decomposed canonically (< modulus). Path elements are free prover
// witnesses, so they only need a range-checked byte decomposition: a
// non-canonical encoding is just another 32-byte sibling and cannot open a root
// without a SHA-256 second preimage.
func Sha256MerkleRoot(api frontend.API, leaf frontend.Variable, index []frontend.Variable, path []frontend.Variable) frontend.Variable {
	if len(index) != len(path) {
		panic(fmt.Sprintf("sha256 merkle: %d index bits for %d path elements", len(index), len(path)))
	}
	bapi, err := uints.NewBytes(api)
	if err != nil {
		panic(err)
	}
	current := canonicalBytesBE(api, bapi, leaf)
	for level := range path {
		sibling := bytesBE(api, bapi, path[level])
		message := make([]uints.U8, 2*Sha256NodeBytes)
		for k := 0; k < Sha256NodeBytes; k++ {
			message[k] = bapi.Select(index[level], sibling[k], current[k])
			message[Sha256NodeBytes+k] = bapi.Select(index[level], current[k], sibling[k])
		}
		hasher, err := sha2.New(api)
		if err != nil {
			panic(err)
		}
		hasher.Write(message)
		current = hasher.Sum()
		current[0] = uints.NewU8(0)
	}
	return packBytesBE(api, bapi, current)
}

// bytesBE decomposes value into 32 range-checked big-endian bytes whose
// recomposition equals value modulo the field.
func bytesBE(api frontend.API, bapi *uints.Bytes, value frontend.Variable) []uints.U8 {
	hinted, err := api.Compiler().NewHint(bytesBEHint, Sha256NodeBytes, value)
	if err != nil {
		panic(err)
	}
	out := make([]uints.U8, Sha256NodeBytes)
	for k := range hinted {
		out[k] = bapi.ValueOf(hinted[k])
	}
	api.AssertIsEqual(packBytesBE(api, bapi, out), value)
	return out
}

// canonicalBytesBE decomposes value into 32 big-endian bytes of its unique
// representative below the modulus.
func canonicalBytesBE(api frontend.API, bapi *uints.Bytes, value frontend.Variable) []uints.U8 {
	bits := api.ToBinary(value, 8*Sha256NodeBytes)
	out := make([]uints.U8, Sha256NodeBytes)
	for k := 0; k < Sha256NodeBytes; k++ {
		lsbByte := Sha256NodeBytes - 1 - k
		b := frontend.Variable(0)
		for j := 0; j < 8; j++ {
			b = api.Add(b, api.Mul(bits[8*lsbByte+j], 1<<j))
		}
		out[k] = bapi.ValueOf(b)
	}
	return out
}

func packBytesBE(api frontend.API, bapi *uints.Bytes, bytes []uints.U8) frontend.Variable {
	acc := frontend.Variable(0)
	coefficient := big.NewInt(1)
	for k := len(bytes) - 1; k >= 0; k-- {
		acc = api.Add(acc, api.Mul(bapi.Value(bytes[k]), new(big.Int).Set(coefficient)))
		coefficient.Lsh(coefficient, 8)
	}
	return acc
}

func bytesBEHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 || len(outputs) != Sha256NodeBytes {
		return fmt.Errorf("bytesBEHint: want 1 input and %d outputs, got %d and %d", Sha256NodeBytes, len(inputs), len(outputs))
	}
	if inputs[0].Sign() < 0 || inputs[0].BitLen() > 8*Sha256NodeBytes {
		return fmt.Errorf("bytesBEHint: input does not fit %d bytes", Sha256NodeBytes)
	}
	var buf [Sha256NodeBytes]byte
	inputs[0].FillBytes(buf[:])
	for k := range outputs {
		outputs[k].SetUint64(uint64(buf[k]))
	}
	return nil
}
