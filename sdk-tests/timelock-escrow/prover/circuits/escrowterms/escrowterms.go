package escrowterms

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

type EscrowTerms struct {
	OwnerHash frontend.Variable
	Unlock    frontend.Variable
}

func (t EscrowTerms) DataHash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{t.OwnerHash, t.Unlock})
}
