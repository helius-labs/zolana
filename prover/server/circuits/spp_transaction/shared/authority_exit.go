package shared

import "github.com/consensys/gnark/frontend"

// A real output leaves only to the default ring.
func AssertRingInputsFreeOutputs(
	api frontend.API,
	inputs []Input,
	outputs []UtxoCircuitFields,
	ringProgramID frontend.Variable,
) {
	for _, in := range inputs {
		AssertWhen(api, in.isUtxo(api), checkRingMembership(api, in.Utxo, ringProgramID, false))
	}
	for _, utxo := range outputs {
		AssertWhen(api, utxo.isUtxo(api), checkRingMembership(api, utxo, ringProgramID, true))
	}
}

// Real default-ring outputs carry a nonzero owner tag.
func AssertExitOwnersNamed(
	api frontend.API,
	outputs []UtxoCircuitFields,
	ownerPkHashes []frontend.Variable,
) error {
	if err := ValidateLength("output owner pk hash", len(ownerPkHashes), len(outputs)); err != nil {
		return err
	}
	for i, utxo := range outputs {
		isExit := api.Mul(utxo.isUtxo(api), api.IsZero(utxo.RingProgramID))
		assertZeroWhen(api, isExit, api.IsZero(ownerPkHashes[i]))
	}
	return nil
}
