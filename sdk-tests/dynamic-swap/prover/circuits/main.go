// Command circuits is built as the dynamic-swap example's C archive: the
// zolana/gnarkprover bridge with the escrow_open and escrow_settle circuits
// registered.
package main

import "C"

import (
	"github.com/consensys/gnark/frontend"

	"circuits/escrow_open"
	"circuits/escrow_settle"
	"zolana/gnarkprover"
)

func init() {
	gnarkprover.Register("escrow_open", gnarkprover.Circuit{
		New: func() frontend.Circuit { return &escrow_open.Circuit{} },
	})
	gnarkprover.Register("escrow_settle", gnarkprover.Circuit{
		New: func() frontend.Circuit { return &escrow_settle.Circuit{} },
	})
}

func main() {}
