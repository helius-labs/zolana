// Command circuits is built as the dynamic-swap example's C archive: the
// zolana/gnarkffiprover bridge with the escrow_open and escrow_settle circuits
// registered.
package main

import "C"

import (
	"github.com/consensys/gnark/frontend"

	"circuits/escrow_open"
	"circuits/escrow_settle"
	"zolana/gnarkffiprover"
)

func init() {
	gnarkffiprover.Register("escrow_open", gnarkffiprover.Circuit{
		New: func() frontend.Circuit { return &escrow_open.Circuit{} },
	})
	gnarkffiprover.Register("escrow_settle", gnarkffiprover.Circuit{
		New: func() frontend.Circuit { return &escrow_settle.Circuit{} },
	})
}

func main() {}
