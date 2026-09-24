// Command circuits is built as the dynamic-swap example's C archive: the
// zolana/gnarkffiprover bridge with the escrow_open, pool_settle,
// escrow_cancel, pool_withdraw and pool_rebalance circuits registered.
package main

import "C"

import (
	"github.com/consensys/gnark/frontend"

	"circuits/escrow_cancel"
	"circuits/escrow_open"
	"circuits/pool_rebalance"
	"circuits/pool_settle"
	"circuits/pool_withdraw"
	"zolana/gnarkffiprover"
)

func init() {
	gnarkffiprover.Register("escrow_open", gnarkffiprover.Circuit{
		New: func() frontend.Circuit { return &escrow_open.Circuit{} },
	})
	gnarkffiprover.Register("pool_settle", gnarkffiprover.Circuit{
		New: func() frontend.Circuit { return &pool_settle.Circuit{} },
	})
	gnarkffiprover.Register("escrow_cancel", gnarkffiprover.Circuit{
		New: func() frontend.Circuit { return &escrow_cancel.Circuit{} },
	})
	gnarkffiprover.Register("pool_withdraw", gnarkffiprover.Circuit{
		New: func() frontend.Circuit { return &pool_withdraw.Circuit{} },
	})
	gnarkffiprover.Register("pool_rebalance", gnarkffiprover.Circuit{
		New: func() frontend.Circuit { return &pool_rebalance.Circuit{} },
	})
}

func main() {}
