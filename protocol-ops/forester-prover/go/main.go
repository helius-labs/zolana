package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"unsafe"

	"github.com/helius-labs/zolana/prover/server/prover/common"
	nullifiertree "github.com/helius-labs/zolana/prover/server/prover/nullifier_tree"
)

var keyCache = struct {
	sync.Mutex
	keys map[string]*common.BatchProofSystem
}{keys: make(map[string]*common.BatchProofSystem)}

func load(path, expected string) (*common.BatchProofSystem, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	keyCache.Lock()
	defer keyCache.Unlock()
	if proofSystem, ok := keyCache.keys[absolute]; ok {
		if hex.EncodeToString(proofSystem.ProvingKeySha256[:]) != expected {
			return nil, fmt.Errorf("cached proving key digest mismatch")
		}
		return proofSystem, nil
	}
	if err := common.EnsureProvingKey(absolute, false, nil); err != nil {
		return nil, err
	}
	system, err := common.ReadSystemFromFile(absolute)
	if err != nil {
		return nil, err
	}
	proofSystem, ok := system.(*common.BatchProofSystem)
	if !ok {
		return nil, fmt.Errorf("key is not a batch proof system")
	}
	if hex.EncodeToString(proofSystem.ProvingKeySha256[:]) != expected {
		return nil, fmt.Errorf("proving key digest mismatch")
	}
	keyCache.keys[absolute] = proofSystem
	return proofSystem, nil
}

func prove(path, expected, body string) (interface{}, error) {
	var params nullifiertree.BatchAddressAppendParameters
	if err := json.Unmarshal([]byte(body), &params); err != nil {
		return nil, err
	}
	if err := params.ValidateShape(); err != nil {
		return nil, err
	}
	proofSystem, err := load(path, expected)
	if err != nil {
		return nil, err
	}
	if proofSystem.TreeHeight != params.TreeHeight || proofSystem.BatchSize != params.BatchSize {
		return nil, fmt.Errorf("key shape does not match proof request")
	}
	return (nullifiertree.BatchAddressAppendProof{System: proofSystem, Parameters: &params}).Prove()
}

func response(value interface{}, err error) *C.char {
	if err != nil {
		value = map[string]string{"error": err.Error()}
	}
	encoded, marshalErr := json.Marshal(value)
	if marshalErr != nil {
		return C.CString(`{"error":"encode proof response"}`)
	}
	return C.CString(string(encoded))
}

//export ForesterProve
func ForesterProve(path, expected, body *C.char) (responseJSON *C.char) {
	defer func() {
		if recovered := recover(); recovered != nil {
			responseJSON = response(nil, fmt.Errorf("gnark panic: %v", recovered))
		}
	}()
	value, err := prove(C.GoString(path), C.GoString(expected), C.GoString(body))
	return response(value, err)
}

//export ForesterFree
func ForesterFree(value *C.char) { C.free(unsafe.Pointer(value)) }

func main() {}
