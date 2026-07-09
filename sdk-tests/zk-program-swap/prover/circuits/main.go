package main

/*
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned char proof_a[64];
    unsigned char proof_b[128];
    unsigned char proof_c[64];
    unsigned char public_input[32];
    unsigned char proof_commitment[64];
    unsigned char proof_commitment_pok[64];
    char *error;
} C_ProveResult;
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"circuits/cancel"
	"circuits/create"
	"circuits/fill"
	"circuits/fill_verifiable_encryption"
	"circuits/stub"
	"circuits/witness"
)

const (
	CircuitStub                     = 0
	CircuitCreate                   = 1
	CircuitCancel                   = 2
	CircuitFill                     = 3
	CircuitFillVerifiableEncryption = 4
)

var (
	cacheMu sync.RWMutex
	csCache = make(map[int]constraint.ConstraintSystem)
	pkCache = make(map[int]groth16.ProvingKey)
	vkCache = make(map[int]groth16.VerifyingKey)
)

func compileCircuit(id int) (constraint.ConstraintSystem, error) {
	cacheMu.RLock()
	if cs, ok := csCache[id]; ok {
		cacheMu.RUnlock()
		return cs, nil
	}
	cacheMu.RUnlock()

	cacheMu.Lock()
	defer cacheMu.Unlock()
	if cs, ok := csCache[id]; ok {
		return cs, nil
	}

	var circuit frontend.Circuit
	var opts []frontend.CompileOption
	switch id {
	case CircuitStub:
		circuit = &stub.Circuit{}
	case CircuitCreate:
		circuit = &create.Circuit{}
	case CircuitCancel:
		circuit = &cancel.Circuit{}
	case CircuitFill:
		circuit = &fill.Circuit{}
	case CircuitFillVerifiableEncryption:
		circuit = &fill_verifiable_encryption.Circuit{}
		opts = append(opts, frontend.WithCompressThreshold(300))
	default:
		return nil, fmt.Errorf("unknown circuit id %d", id)
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, opts...)
	if err != nil {
		return nil, fmt.Errorf("compile circuit %d: %w", id, err)
	}
	csCache[id] = cs
	return cs, nil
}

func assignFromWitness(id int, witnessValues map[string][]string) (frontend.Circuit, error) {
	var circuit frontend.Circuit
	switch id {
	case CircuitStub:
		circuit = &stub.Circuit{}
	case CircuitCreate:
		circuit = &create.Circuit{}
	case CircuitCancel:
		circuit = &cancel.Circuit{}
	case CircuitFill:
		circuit = &fill.Circuit{}
	case CircuitFillVerifiableEncryption:
		circuit = &fill_verifiable_encryption.Circuit{}
	default:
		return nil, fmt.Errorf("unknown circuit id %d", id)
	}
	if err := witness.Assign(circuit, witnessValues); err != nil {
		return nil, err
	}
	return circuit, nil
}

func writeProvingKey(pk groth16.ProvingKey, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := pk.WriteTo(f); err != nil {
		return fmt.Errorf("pk WriteTo: %w", err)
	}
	return nil
}

func writeVerifyingKey(vk groth16.VerifyingKey, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	vkBN, ok := vk.(*groth16_bn254.VerifyingKey)
	if !ok {
		return fmt.Errorf("unexpected verifying key type %T", vk)
	}
	if _, err := vkBN.WriteRawTo(f); err != nil {
		return fmt.Errorf("vk WriteRawTo: %w", err)
	}
	return nil
}

//export Setup
func Setup(circuitID C.int, outDir *C.char) *C.char {
	id := int(circuitID)
	dir := C.GoString(outDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return C.CString(fmt.Sprintf("mkdir %s: %v", dir, err))
	}

	cs, err := compileCircuit(id)
	if err != nil {
		return C.CString(err.Error())
	}

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return C.CString(fmt.Sprintf("setup: %v", err))
	}

	if err := writeProvingKey(pk, filepath.Join(dir, "pk.bin")); err != nil {
		return C.CString(err.Error())
	}
	if err := writeVerifyingKey(vk, filepath.Join(dir, "vk.bin")); err != nil {
		return C.CString(err.Error())
	}

	cacheMu.Lock()
	pkCache[id] = pk
	vkCache[id] = vk
	cacheMu.Unlock()

	return nil
}

//export LoadKeys
func LoadKeys(circuitID C.int, pkPath *C.char, vkPath *C.char) *C.char {
	id := int(circuitID)
	pkPathStr := C.GoString(pkPath)
	vkPathStr := C.GoString(vkPath)

	if _, err := compileCircuit(id); err != nil {
		return C.CString(err.Error())
	}

	pk := groth16.NewProvingKey(ecc.BN254)
	pkF, err := os.Open(pkPathStr)
	if err != nil {
		return C.CString(fmt.Sprintf("open pk %s: %v", pkPathStr, err))
	}
	defer pkF.Close()
	if _, err := pk.ReadFrom(pkF); err != nil {
		return C.CString(fmt.Sprintf("read pk: %v", err))
	}

	vk := groth16.NewVerifyingKey(ecc.BN254)
	vkF, err := os.Open(vkPathStr)
	if err != nil {
		return C.CString(fmt.Sprintf("open vk %s: %v", vkPathStr, err))
	}
	defer vkF.Close()
	if _, err := vk.ReadFrom(vkF); err != nil {
		return C.CString(fmt.Sprintf("read vk: %v", err))
	}

	cacheMu.Lock()
	pkCache[id] = pk
	vkCache[id] = vk
	cacheMu.Unlock()

	return nil
}

//export Prove
func Prove(circuitID C.int, witnessJSON *C.char) (ret *C.C_ProveResult) {
	result := (*C.C_ProveResult)(C.malloc(C.sizeof_C_ProveResult))
	C.memset(unsafe.Pointer(result), 0, C.sizeof_C_ProveResult)

	defer func() {
		if r := recover(); r != nil {
			result.error = C.CString(fmt.Sprintf("prove panic: %v", r))
			ret = result
		}
	}()

	id := int(circuitID)

	var witnessValues map[string][]string
	if err := json.Unmarshal([]byte(C.GoString(witnessJSON)), &witnessValues); err != nil {
		result.error = C.CString(fmt.Sprintf("witness json: %v", err))
		return result
	}

	cs, err := compileCircuit(id)
	if err != nil {
		result.error = C.CString(err.Error())
		return result
	}

	cacheMu.RLock()
	pk, pkOk := pkCache[id]
	cacheMu.RUnlock()
	if !pkOk {
		result.error = C.CString(fmt.Sprintf("circuit %d: proving key not loaded -- call Setup or LoadKeys first", id))
		return result
	}

	assignment, err := assignFromWitness(id, witnessValues)
	if err != nil {
		result.error = C.CString(err.Error())
		return result
	}

	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		result.error = C.CString(fmt.Sprintf("new witness: %v", err))
		return result
	}

	proof, err := groth16.Prove(cs, pk, w)
	if err != nil {
		result.error = C.CString(fmt.Sprintf("prove: %v", err))
		return result
	}

	proofBN, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		result.error = C.CString(fmt.Sprintf("unexpected proof type %T", proof))
		return result
	}

	arRaw := proofBN.Ar.RawBytes()
	bsRaw := proofBN.Bs.RawBytes()
	krsRaw := proofBN.Krs.RawBytes()

	if err := copyBytes(&result.proof_a[0], arRaw[:]); err != nil {
		result.error = C.CString(err.Error())
		return result
	}
	if err := copyBytes(&result.proof_b[0], bsRaw[:128]); err != nil {
		result.error = C.CString(err.Error())
		return result
	}
	if err := copyBytes(&result.proof_c[0], krsRaw[:]); err != nil {
		result.error = C.CString(err.Error())
		return result
	}

	if len(proofBN.Commitments) > 1 {
		result.error = C.CString(fmt.Sprintf(
			"prove: circuit %d produced %d commitments, only 1 is supported by groth16-solana BSB22 path",
			id, len(proofBN.Commitments)))
		return result
	}
	if len(proofBN.Commitments) == 1 {
		commRaw := proofBN.Commitments[0].RawBytes()
		if err := copyBytes(&result.proof_commitment[0], commRaw[:]); err != nil {
			result.error = C.CString(err.Error())
			return result
		}
		pokRaw := proofBN.CommitmentPok.RawBytes()
		if err := copyBytes(&result.proof_commitment_pok[0], pokRaw[:]); err != nil {
			result.error = C.CString(err.Error())
			return result
		}
	}

	publicWitness, err := w.Public()
	if err != nil {
		result.error = C.CString(fmt.Sprintf("public witness: %v", err))
		return result
	}
	publicVector, ok := publicWitness.Vector().(fr.Vector)
	if !ok {
		result.error = C.CString(fmt.Sprintf("public witness: unexpected vector type %T", publicWitness.Vector()))
		return result
	}
	if len(publicVector) != 1 {
		result.error = C.CString(fmt.Sprintf("public witness: expected 1 element, got %d", len(publicVector)))
		return result
	}
	pubInputBytes := publicVector[0].Bytes()
	if err := copyBytes(&result.public_input[0], pubInputBytes[:]); err != nil {
		result.error = C.CString(err.Error())
		return result
	}

	return result
}

func copyBytes(dst *C.uchar, src []byte) error {
	if dst == nil {
		return fmt.Errorf("copyBytes: nil dst")
	}
	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(dst)), len(src))
	copy(dstSlice, src)
	return nil
}

//export FreeProveResult
func FreeProveResult(result *C.C_ProveResult) {
	if result == nil {
		return
	}
	if result.error != nil {
		C.free(unsafe.Pointer(result.error))
	}
	C.free(unsafe.Pointer(result))
}

//export FreeString
func FreeString(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

func main() {}
