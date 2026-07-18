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

	"circuits/escrow"
	"circuits/withdraw"
	"circuits/witness"
)

const (
	CircuitEscrow   = 0
	CircuitWithdraw = 1
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
	switch id {
	case CircuitEscrow:
		circuit = &escrow.Circuit{}
	case CircuitWithdraw:
		circuit = &withdraw.Circuit{}
	default:
		return nil, fmt.Errorf("unknown circuit id %d", id)
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("compile circuit %d: %w", id, err)
	}
	csCache[id] = cs
	return cs, nil
}

func assignFromWitness(id int, witnessValues map[string][]string) (frontend.Circuit, error) {
	var circuit frontend.Circuit
	switch id {
	case CircuitEscrow:
		circuit = &escrow.Circuit{}
	case CircuitWithdraw:
		circuit = &withdraw.Circuit{}
	default:
		return nil, fmt.Errorf("unknown circuit id %d", id)
	}
	if err := witness.Assign(circuit, witnessValues); err != nil {
		return nil, err
	}
	return circuit, nil
}

func writeProvingKey(pk groth16.ProvingKey, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := pk.WriteTo(file); err != nil {
		return fmt.Errorf("pk WriteTo: %w", err)
	}
	return nil
}

func writeVerifyingKey(vk groth16.VerifyingKey, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	vkBN, ok := vk.(*groth16_bn254.VerifyingKey)
	if !ok {
		return fmt.Errorf("unexpected verifying key type %T", vk)
	}
	if _, err := vkBN.WriteRawTo(file); err != nil {
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
	proveResult := (*C.C_ProveResult)(C.malloc(C.sizeof_C_ProveResult))
	C.memset(unsafe.Pointer(proveResult), 0, C.sizeof_C_ProveResult)

	defer func() {
		if r := recover(); r != nil {
			proveResult.error = C.CString(fmt.Sprintf("prove panic: %v", r))
			ret = proveResult
		}
	}()

	id := int(circuitID)

	var witnessValues map[string][]string
	if err := json.Unmarshal([]byte(C.GoString(witnessJSON)), &witnessValues); err != nil {
		proveResult.error = C.CString(fmt.Sprintf("witness json: %v", err))
		return proveResult
	}

	cs, err := compileCircuit(id)
	if err != nil {
		proveResult.error = C.CString(err.Error())
		return proveResult
	}

	cacheMu.RLock()
	pk, pkOk := pkCache[id]
	cacheMu.RUnlock()
	if !pkOk {
		proveResult.error = C.CString(fmt.Sprintf("circuit %d: proving key not loaded -- call Setup or LoadKeys first", id))
		return proveResult
	}

	assignment, err := assignFromWitness(id, witnessValues)
	if err != nil {
		proveResult.error = C.CString(err.Error())
		return proveResult
	}

	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		proveResult.error = C.CString(fmt.Sprintf("new witness: %v", err))
		return proveResult
	}

	proof, err := groth16.Prove(cs, pk, fullWitness)
	if err != nil {
		proveResult.error = C.CString(fmt.Sprintf("prove: %v", err))
		return proveResult
	}

	proofBN, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		proveResult.error = C.CString(fmt.Sprintf("unexpected proof type %T", proof))
		return proveResult
	}

	arRaw := proofBN.Ar.RawBytes()
	bsRaw := proofBN.Bs.RawBytes()
	krsRaw := proofBN.Krs.RawBytes()

	if err := copyBytes(&proveResult.proof_a[0], arRaw[:]); err != nil {
		proveResult.error = C.CString(err.Error())
		return proveResult
	}
	if err := copyBytes(&proveResult.proof_b[0], bsRaw[:128]); err != nil {
		proveResult.error = C.CString(err.Error())
		return proveResult
	}
	if err := copyBytes(&proveResult.proof_c[0], krsRaw[:]); err != nil {
		proveResult.error = C.CString(err.Error())
		return proveResult
	}

	if len(proofBN.Commitments) != 0 {
		proveResult.error = C.CString(fmt.Sprintf(
			"prove: circuit %d produced %d commitments, timelock-escrow circuits are standard Groth16 (no BSB22 commitment)",
			id, len(proofBN.Commitments)))
		return proveResult
	}

	publicWitness, err := fullWitness.Public()
	if err != nil {
		proveResult.error = C.CString(fmt.Sprintf("public witness: %v", err))
		return proveResult
	}
	publicVector, ok := publicWitness.Vector().(fr.Vector)
	if !ok {
		proveResult.error = C.CString(fmt.Sprintf("public witness: unexpected vector type %T", publicWitness.Vector()))
		return proveResult
	}
	if len(publicVector) != 1 {
		proveResult.error = C.CString(fmt.Sprintf("public witness: expected 1 element, got %d", len(publicVector)))
		return proveResult
	}
	pubInputBytes := publicVector[0].Bytes()
	if err := copyBytes(&proveResult.public_input[0], pubInputBytes[:]); err != nil {
		proveResult.error = C.CString(err.Error())
		return proveResult
	}

	return proveResult
}

func copyBytes(destination *C.uchar, source []byte) error {
	if destination == nil {
		return fmt.Errorf("copyBytes: nil destination")
	}
	destinationSlice := unsafe.Slice((*byte)(unsafe.Pointer(destination)), len(source))
	copy(destinationSlice, source)
	return nil
}

//export FreeProveResult
func FreeProveResult(proveResult *C.C_ProveResult) {
	if proveResult == nil {
		return
	}
	if proveResult.error != nil {
		C.free(unsafe.Pointer(proveResult.error))
	}
	C.free(unsafe.Pointer(proveResult))
}

//export FreeString
func FreeString(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

func main() {}
