// Command circuits is built as the timelock-escrow example's C archive: the
// zolana/gnarkprover bridge with the escrow and withdraw circuits registered.
package main

import "C"

import (
	"github.com/consensys/gnark/frontend"

	"circuits/escrow"
	"circuits/withdraw"
	"zolana/gnarkprover"
)

func init() {
	gnarkprover.Register("escrow", gnarkprover.Circuit{
		New: func() frontend.Circuit { return &escrow.Circuit{} },
	})
	gnarkprover.Register("withdraw", gnarkprover.Circuit{
		New: func() frontend.Circuit { return &withdraw.Circuit{} },
	})
}

func main() {}
