// Package gnarkprover is the cgo bridge every sdk-tests example prover builds
// into its Rust crate as a C archive. An example's `main` package registers
// its circuits by name from an init function; the exported Setup, LoadKeys and
// Prove look a circuit up by that name, which is also its key directory and
// setup CLI argument on the Rust side (`zolana_gnark_prover::Circuit::name`).
package gnarkprover

/*
#include <stdlib.h>
#include <string.h>

// Mirrored field for field by `ProveResult` in sdk-libs/gnark-prover/src/ffi.rs.
typedef struct {
    unsigned char proof_a[64];
    unsigned char proof_b[128];
    unsigned char proof_c[64];
    unsigned char public_input[32];
    unsigned char has_commitment;
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
)

// Circuit is one registered circuit.
type Circuit struct {
	// New returns an empty circuit value, used both to compile the constraint
	// system and as the target of each witness assignment.
	New func() frontend.Circuit
	// CompileOptions must be the options the committed keys were set up
	// with: a different option set compiles a different constraint system.
	CompileOptions []frontend.CompileOption
	// Commitments is the number of BSB22 commitments every proof carries: 0
	// for standard Groth16, 1 when a gadget commits to private wires.
	// groth16-solana verifies at most one, and Prove rejects any other count.
	Commitments int
}

var (
	mu          sync.RWMutex
	circuits    = map[string]Circuit{}
	compiled    = map[string]constraint.ConstraintSystem{}
	provingKeys = map[string]groth16.ProvingKey{}
)

// Register adds a circuit under name. It is meant for init functions and
// panics on a duplicate name or an unsupported commitment count, both of which
// are mistakes in the example's registration code.
func Register(name string, circuit Circuit) {
	if circuit.Commitments < 0 || circuit.Commitments > 1 {
		panic(fmt.Sprintf("gnarkprover: circuit %q declares %d commitments, groth16-solana verifies at most 1", name, circuit.Commitments))
	}
	mu.Lock()
	defer mu.Unlock()
	if _, ok := circuits[name]; ok {
		panic(fmt.Sprintf("gnarkprover: circuit %q registered twice", name))
	}
	circuits[name] = circuit
}

func lookup(name string) (Circuit, error) {
	mu.RLock()
	defer mu.RUnlock()
	circuit, ok := circuits[name]
	if !ok {
		return Circuit{}, fmt.Errorf("unknown circuit %q", name)
	}
	return circuit, nil
}

func compile(name string) (constraint.ConstraintSystem, error) {
	circuit, err := lookup(name)
	if err != nil {
		return nil, err
	}
	mu.RLock()
	cs, ok := compiled[name]
	mu.RUnlock()
	if ok {
		return cs, nil
	}

	mu.Lock()
	defer mu.Unlock()
	if cs, ok := compiled[name]; ok {
		return cs, nil
	}
	cs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit.New(), circuit.CompileOptions...)
	if err != nil {
		return nil, fmt.Errorf("compile circuit %q: %w", name, err)
	}
	compiled[name] = cs
	return cs, nil
}

func setProvingKey(name string, pk groth16.ProvingKey) {
	mu.Lock()
	provingKeys[name] = pk
	mu.Unlock()
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

// The verifying key is written raw (uncompressed), the encoding
// groth16_solana::vk::gnark parses into the committed Rust verifying key.
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

func setup(name, dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	cs, err := compile(name)
	if err != nil {
		return err
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	if err := writeProvingKey(pk, filepath.Join(dir, "pk.bin")); err != nil {
		return err
	}
	if err := writeVerifyingKey(vk, filepath.Join(dir, "vk.bin")); err != nil {
		return err
	}
	setProvingKey(name, pk)
	return nil
}

func loadKeys(name, pkPath string) error {
	if _, err := compile(name); err != nil {
		return err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	file, err := os.Open(pkPath)
	if err != nil {
		return fmt.Errorf("open pk %s: %w", pkPath, err)
	}
	defer file.Close()
	if _, err := pk.ReadFrom(file); err != nil {
		return fmt.Errorf("read pk %s: %w", pkPath, err)
	}
	setProvingKey(name, pk)
	return nil
}

func errorString(err error) *C.char {
	if err == nil {
		return nil
	}
	return C.CString(err.Error())
}

// Setup generates fresh keys for the circuit, writes pk.bin and vk.bin into
// outDir and keeps the proving key loaded. It returns NULL or an error string
// the caller frees with FreeString.
//
//export Setup
func Setup(name, outDir *C.char) *C.char {
	return errorString(setup(C.GoString(name), C.GoString(outDir)))
}

// LoadKeys loads the circuit's proving key from pkPath. It returns NULL or an
// error string the caller frees with FreeString.
//
//export LoadKeys
func LoadKeys(name, pkPath *C.char) *C.char {
	return errorString(loadKeys(C.GoString(name), C.GoString(pkPath)))
}

// Prove proves the witness, a JSON object from witness key to decimal field
// values, against the circuit's loaded proving key. The caller frees the
// result with FreeProveResult; on failure only its error is set.
//
//export Prove
func Prove(name, witnessJSON *C.char) (ret *C.C_ProveResult) {
	result := (*C.C_ProveResult)(C.malloc(C.sizeof_C_ProveResult))
	C.memset(unsafe.Pointer(result), 0, C.sizeof_C_ProveResult)
	defer func() {
		if r := recover(); r != nil {
			result.error = C.CString(fmt.Sprintf("prove panic: %v", r))
			ret = result
		}
	}()
	if err := prove(C.GoString(name), C.GoString(witnessJSON), result); err != nil {
		result.error = C.CString(err.Error())
	}
	return result
}

func prove(name, witnessJSON string, result *C.C_ProveResult) error {
	var values map[string][]string
	if err := json.Unmarshal([]byte(witnessJSON), &values); err != nil {
		return fmt.Errorf("witness json: %w", err)
	}
	circuit, err := lookup(name)
	if err != nil {
		return err
	}
	cs, err := compile(name)
	if err != nil {
		return err
	}
	mu.RLock()
	pk, ok := provingKeys[name]
	mu.RUnlock()
	if !ok {
		return fmt.Errorf("circuit %q: proving key not loaded -- call Setup or LoadKeys first", name)
	}

	assignment := circuit.New()
	if err := assign(assignment, values); err != nil {
		return err
	}
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("new witness: %w", err)
	}
	proof, err := groth16.Prove(cs, pk, fullWitness)
	if err != nil {
		return fmt.Errorf("prove: %w", err)
	}
	proofBN, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		return fmt.Errorf("unexpected proof type %T", proof)
	}
	if len(proofBN.Commitments) != circuit.Commitments {
		return fmt.Errorf("circuit %q produced %d BSB22 commitments, registered with %d",
			name, len(proofBN.Commitments), circuit.Commitments)
	}

	ar := proofBN.Ar.RawBytes()
	bs := proofBN.Bs.RawBytes()
	krs := proofBN.Krs.RawBytes()
	copyBytes(&result.proof_a[0], ar[:])
	copyBytes(&result.proof_b[0], bs[:])
	copyBytes(&result.proof_c[0], krs[:])
	if circuit.Commitments == 1 {
		commitment := proofBN.Commitments[0].RawBytes()
		pok := proofBN.CommitmentPok.RawBytes()
		result.has_commitment = 1
		copyBytes(&result.proof_commitment[0], commitment[:])
		copyBytes(&result.proof_commitment_pok[0], pok[:])
	}

	// Every example circuit exposes a single public input, the hash of its
	// public values.
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return fmt.Errorf("public witness: %w", err)
	}
	publicVector, ok := publicWitness.Vector().(fr.Vector)
	if !ok {
		return fmt.Errorf("public witness: unexpected vector type %T", publicWitness.Vector())
	}
	if len(publicVector) != 1 {
		return fmt.Errorf("public witness: expected 1 element, got %d", len(publicVector))
	}
	publicInput := publicVector[0].Bytes()
	copyBytes(&result.public_input[0], publicInput[:])
	return nil
}

func copyBytes(destination *C.uchar, source []byte) {
	copy(unsafe.Slice((*byte)(unsafe.Pointer(destination)), len(source)), source)
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
