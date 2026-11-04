package shared

import "github.com/consensys/gnark/frontend"

// Real inputs stay in the signing ring, and only a real output may leave to the default ring.
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

// A zero tag on a real default-ring output would hide the exit among ring outputs.
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
