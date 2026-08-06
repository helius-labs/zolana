package gadget

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
)

// OpenEmulatedInput reads one emulated inner public input as a native variable.
//
// ToBitsCanonical asserts the decomposition is below the modulus, so one
// element maps to one native value. A plain limb recomposition would admit a
// second representation and let an outer proof claim a public input it did not
// verify.
func OpenEmulatedInput(
	api frontend.API,
	field *emulated.Field[sw_bn254.ScalarField],
	value *emulated.Element[sw_bn254.ScalarField],
) frontend.Variable {
	return bits.FromBinary(api, field.ToBitsCanonical(value))
}

// OpenPublicInput binds a witnessed preimage to an inner proof's public input.
//
// An outer circuit that only chains opaque public inputs cannot constrain what
// is inside them. Opening one lets a fold assert continuity between legs, such
// as one leg's new root being the next leg's old root. Without the binding a
// prover could claim any preimage for a public input it did prove, and every
// continuity check downstream would be vacuous.
//
// preimage must be the exact hash-chain input the inner circuit committed to,
// in order. HashChain is a left fold, so a permutation is a different value.
func OpenPublicInput(
	api frontend.API,
	field *emulated.Field[sw_bn254.ScalarField],
	value *emulated.Element[sw_bn254.ScalarField],
	preimage []frontend.Variable,
) (frontend.Variable, error) {
	if len(preimage) == 0 {
		return nil, fmt.Errorf("empty preimage")
	}
	opened := OpenEmulatedInput(api, field, value)
	api.AssertIsEqual(opened, HashChain(api, preimage))
	return opened, nil
}
