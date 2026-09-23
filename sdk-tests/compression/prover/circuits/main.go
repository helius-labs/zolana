package main

/*
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned char proof_a[64];
    unsigned char proof_b[128];
    unsigned char proof_c[64];
    unsigned char public_input[32];
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

	"circuits/read"
	"circuits/witness"
)

var (
	compileOnce sync.Once
	cs          constraint.ConstraintSystem
	compileErr  error

	keyMu sync.RWMutex
	pk    groth16.ProvingKey
)

func compileCircuit() (constraint.ConstraintSystem, error) {
	compileOnce.Do(func() {
		cs, compileErr = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &read.Circuit{})
		if compileErr != nil {
			compileErr = fmt.Errorf("compile read circuit: %w", compileErr)
		}
	})
	return cs, compileErr
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
func Setup(outDir *C.char) *C.char {
	dir := C.GoString(outDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return C.CString(fmt.Sprintf("mkdir %s: %v", dir, err))
	}

	cs, err := compileCircuit()
	if err != nil {
		return C.CString(err.Error())
	}

	newPk, vk, err := groth16.Setup(cs)
	if err != nil {
		return C.CString(fmt.Sprintf("setup: %v", err))
	}

	if err := writeProvingKey(newPk, filepath.Join(dir, "pk.bin")); err != nil {
		return C.CString(err.Error())
	}
	if err := writeVerifyingKey(vk, filepath.Join(dir, "vk.bin")); err != nil {
		return C.CString(err.Error())
	}

	keyMu.Lock()
	pk = newPk
	keyMu.Unlock()
	return nil
}

//export LoadKeys
func LoadKeys(pkPath *C.char) *C.char {
	pkPathStr := C.GoString(pkPath)

	if _, err := compileCircuit(); err != nil {
		return C.CString(err.Error())
	}

	loaded := groth16.NewProvingKey(ecc.BN254)
	pkF, err := os.Open(pkPathStr)
	if err != nil {
		return C.CString(fmt.Sprintf("open pk %s: %v", pkPathStr, err))
	}
	defer pkF.Close()
	if _, err := loaded.ReadFrom(pkF); err != nil {
		return C.CString(fmt.Sprintf("read pk: %v", err))
	}

	keyMu.Lock()
	pk = loaded
	keyMu.Unlock()
	return nil
}

//export Prove
func Prove(witnessJSON *C.char) (ret *C.C_ProveResult) {
	proveResult := (*C.C_ProveResult)(C.malloc(C.sizeof_C_ProveResult))
	C.memset(unsafe.Pointer(proveResult), 0, C.sizeof_C_ProveResult)

	defer func() {
		if r := recover(); r != nil {
			proveResult.error = C.CString(fmt.Sprintf("prove panic: %v", r))
			ret = proveResult
		}
	}()

	var witnessValues map[string][]string
	if err := json.Unmarshal([]byte(C.GoString(witnessJSON)), &witnessValues); err != nil {
		proveResult.error = C.CString(fmt.Sprintf("witness json: %v", err))
		return proveResult
	}

	cs, err := compileCircuit()
	if err != nil {
		proveResult.error = C.CString(err.Error())
		return proveResult
	}

	keyMu.RLock()
	provingKey := pk
	keyMu.RUnlock()
	if provingKey == nil {
		proveResult.error = C.CString("read: proving key not loaded -- call Setup or LoadKeys first")
		return proveResult
	}

	assignment := &read.Circuit{}
	if err := witness.Assign(assignment, witnessValues); err != nil {
		proveResult.error = C.CString(err.Error())
		return proveResult
	}

	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		proveResult.error = C.CString(fmt.Sprintf("new witness: %v", err))
		return proveResult
	}

	proof, err := groth16.Prove(cs, provingKey, fullWitness)
	if err != nil {
		proveResult.error = C.CString(fmt.Sprintf("prove: %v", err))
		return proveResult
	}

	proofBN, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		proveResult.error = C.CString(fmt.Sprintf("unexpected proof type %T", proof))
		return proveResult
	}
	if len(proofBN.Commitments) != 0 {
		proveResult.error = C.CString(fmt.Sprintf(
			"prove: read circuit produced %d commitments, it is standard Groth16 (no BSB22 commitment)",
			len(proofBN.Commitments)))
		return proveResult
	}

	arRaw := proofBN.Ar.RawBytes()
	bsRaw := proofBN.Bs.RawBytes()
	krsRaw := proofBN.Krs.RawBytes()
	copyBytes(&proveResult.proof_a[0], arRaw[:])
	copyBytes(&proveResult.proof_b[0], bsRaw[:128])
	copyBytes(&proveResult.proof_c[0], krsRaw[:])

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
	copyBytes(&proveResult.public_input[0], pubInputBytes[:])

	return proveResult
}

func copyBytes(destination *C.uchar, source []byte) {
	destinationSlice := unsafe.Slice((*byte)(unsafe.Pointer(destination)), len(source))
	copy(destinationSlice, source)
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
