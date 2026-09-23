// Command circuits is built as the swap example's C archive: the
// zolana/gnarkffiprover bridge with the make, cancel, take and
// take_verifiable_encryption circuits registered.
package main

import "C"

import (
	"github.com/consensys/gnark/frontend"

	"circuits/cancel"
	makecircuit "circuits/make"
	"circuits/take"
	"circuits/take_verifiable_encryption"
	"zolana/gnarkffiprover"
)

func init() {
	gnarkffiprover.Register("make", gnarkffiprover.Circuit{
		New: func() frontend.Circuit { return &makecircuit.Circuit{} },
	})
	gnarkffiprover.Register("cancel", gnarkffiprover.Circuit{
		New: func() frontend.Circuit { return &cancel.Circuit{} },
	})
	gnarkffiprover.Register("take", gnarkffiprover.Circuit{
		New: func() frontend.Circuit { return &take.Circuit{} },
	})
	// The verifiable-encryption gadgets add one BSB22 commitment over private
	// wires, and the committed keys were set up with this compress threshold.
	gnarkffiprover.Register("take_verifiable_encryption", gnarkffiprover.Circuit{
		New:            func() frontend.Circuit { return &take_verifiable_encryption.Circuit{} },
		CompileOptions: []frontend.CompileOption{frontend.WithCompressThreshold(300)},
		Commitments:    1,
	})
}

func main() {}
