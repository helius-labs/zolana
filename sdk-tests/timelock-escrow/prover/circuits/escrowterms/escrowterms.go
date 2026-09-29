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

type Funding struct {
	OwnerHash frontend.Variable
}

func (f Funding) DataHash(api frontend.API) frontend.Variable {
	return gnarksdk.Poseidon(api, f.OwnerHash)
}
