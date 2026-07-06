package stub

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

type Circuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	A frontend.Variable
	B frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	h := gadget.PoseidonHash(api, []frontend.Variable{c.A, c.B})
	api.AssertIsEqual(c.PublicInputHash, h)
	return nil
}
