// Command circuits is built as the timelock-escrow example's C archive: the
// zolana/gnarkffiprover bridge with the escrow and withdraw circuits registered.
package main

import "C"

import (
	"github.com/consensys/gnark/frontend"

	"circuits/escrow"
	"circuits/withdraw"
	"zolana/gnarkffiprover"
)

func init() {
	gnarkffiprover.Register("escrow", gnarkffiprover.Circuit{
		New: func() frontend.Circuit { return &escrow.Circuit{} },
	})
	gnarkffiprover.Register("withdraw", gnarkffiprover.Circuit{
		New: func() frontend.Circuit { return &withdraw.Circuit{} },
	})
}

func main() {}
