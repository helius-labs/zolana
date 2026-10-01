// Command circuits is built as the compression example's C archive: the
// zolana/gnarkffiprover bridge with the read circuit registered.
package main

import "C"

import (
	"github.com/consensys/gnark/frontend"

	"circuits/read"
	"zolana/gnarkffiprover"
)

func init() {
	gnarkffiprover.Register("read", gnarkffiprover.Circuit{
		New: func() frontend.Circuit { return &read.Circuit{} },
	})
}

func main() {}
