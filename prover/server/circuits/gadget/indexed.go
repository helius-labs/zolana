package gadget

import (
	"github.com/consensys/gnark/frontend"
)

func IndexedLeafHash(api frontend.API, value, nextValue frontend.Variable) frontend.Variable {
	return TreeHash(api, value, nextValue)
}
