//go:build js && wasm

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall/js"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	native "github.com/consensys/gnark/backend/groth16/bn254"
)

type browserKernel struct {
	key    js.Value
	solver bool
}

func prepareKernel(c *preparedCircuit) {
	// Small circuits cost less in the existing Go implementation.
	constructor := js.Global().Get("__moproGnarkKernel")
	if c.pk == nil || c.cs.GetNbConstraints() < 1024 || constructor.Type() != js.TypeFunction {
		return
	}
	pk := c.pk.(*native.ProvingKey)
	kernel := &browserKernel{key: constructor.New(packKernel(pk.G1.A), packKernel(pk.G1.B), packKernel(pk.G1.K), packKernel(pk.G1.Z), packKernel(pk.G2.B), packKernel([]fr.Element{pk.Domain.Generator, pk.Domain.FrMultiplicativeGen}))}
	installed := false
	defer func() {
		if !installed {
			kernel.close()
		}
	}()
	for _, commitment := range pk.CommitmentKeys {
		kernel.key.Call("add_commitment", packKernel(commitment.Basis), packKernel(commitment.BasisExpSigma))
	}
	if program := kernelSolverProgram(c.cs, pk.InfinityA, pk.InfinityB); program != nil {
		kernel.solver = kernel.key.Call("set_solver", packKernel(program), packKernelFields(c.cs.Coefficients)).Bool()
	}
	c.kernel = kernel
	installed = true
}

// Gnark and arkworks use the same four little-endian Montgomery limbs.
// Only decoded keys, validated solver plans and field elements cross this bridge.
func packKernel(value any) js.Value {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, value); err != nil {
		panic(err)
	}
	out := js.Global().Get("Uint8Array").New(buf.Len())
	js.CopyBytesToJS(out, buf.Bytes())
	return out
}

func packKernelFields(values []fr.Element) js.Value {
	data := encodeKernelFields(values)
	out := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(out, data)
	return out
}

func (k *browserKernel) parts(sa, sb, sk, a, b, c []fr.Element) (kernelParts, error) {
	result := k.key.Call("parts", packKernelFields(sa), packKernelFields(sb), packKernelFields(sk), packKernelFields(a), packKernelFields(b), packKernelFields(c))
	return unpackKernelParts(result)
}
func (k *browserKernel) solveParts(witness []fr.Element) (kernelParts, bool, error) {
	if !k.solver {
		return kernelParts{}, false, nil
	}
	parts, err := unpackKernelParts(k.key.Call("solve_parts", packKernelFields(witness)))
	return parts, true, err
}
func unpackKernelParts(result js.Value) (kernelParts, error) {
	var out kernelParts
	data := byteArray(result)
	if len(data) != 384 {
		return out, fmt.Errorf("invalid accelerated proof parts")
	}
	reader := bytes.NewReader(data)
	for _, point := range []any{&out.a, &out.b, &out.k, &out.z, &out.b2} {
		if err := binary.Read(reader, binary.LittleEndian, point); err != nil {
			return out, err
		}
	}
	return out, nil
}
func (k *browserKernel) close() { k.key.Call("free") }

func (k *browserKernel) commitment(index int, knowledge bool, values []fr.Element) (curve.G1Affine, error) {
	var out curve.G1Affine
	data := byteArray(k.key.Call("commitment", index, knowledge, packKernelFields(values)))
	if len(data) != 64 {
		return out, fmt.Errorf("invalid accelerated commitment")
	}
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &out)
	return out, err
}
