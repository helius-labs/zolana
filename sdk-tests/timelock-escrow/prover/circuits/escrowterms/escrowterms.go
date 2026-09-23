package escrowterms

import (
	"github.com/consensys/gnark/frontend"

	"zolana/gnarksdk"
)

type EscrowTerms struct {
	OwnerHash frontend.Variable
	Unlock    frontend.Variable
}

func (t EscrowTerms) DataHash(api frontend.API) frontend.Variable {
	return gnarksdk.Poseidon(api, t.OwnerHash, t.Unlock)
}
