// Command circuits is built as the squads prover's C archive: the
// zolana/gnarkffiprover bridge with the squads ring and key encryption
// circuits registered.
package main

import "C"

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	keyencryption "circuits/key_encryption"
	squadsring "circuits/ring"
	"zolana/gnarkffiprover"
)

// The shared lookup gadgets add one BSB22 commitment over private variables,
// and the keys are set up with this compress threshold.
var compileOptions = []frontend.CompileOption{frontend.WithCompressThreshold(300)}

func register(name string, newCircuit func() frontend.Circuit) {
	gnarkffiprover.Register(name, gnarkffiprover.Circuit{
		New:            newCircuit,
		CompileOptions: compileOptions,
		Commitments:    1,
	})
}

func init() {
	register("ring_1_1", func() frontend.Circuit { return squadsring.NewWithdrawalCircuit(1) })
	register("ring_2_2", func() frontend.Circuit { return squadsring.NewTransferCircuit(2) })
	for _, numKeys := range []int{1, 2, 3} {
		numKeys := numKeys
		register(fmt.Sprintf("key_encryption_%d", numKeys), func() frontend.Circuit {
			return keyencryption.NewKeyEncryptionCircuit(numKeys)
		})
	}
}

func main() {}
