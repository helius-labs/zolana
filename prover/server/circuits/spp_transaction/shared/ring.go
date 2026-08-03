package shared

import "github.com/consensys/gnark/frontend"

// AssertInDefaultRing — default ring: no utxo may be a member of a ring.
func AssertInDefaultRing(api frontend.API, inputs []Input, outputs []UtxoCircuitFields) {
	for _, in := range inputs {
		in.Utxo.assertInDefaultRing(api)
	}
	for _, utxo := range outputs {
		utxo.assertInDefaultRing(api)
	}
}

// AssertRingMemberOrFree — custom ring: every real utxo either belongs to the
// signing ring or to the default ring.
// Ring data requires a ring program.
func AssertRingMemberOrFree(api frontend.API, inputs []Input, outputs []UtxoCircuitFields, ringProgramID frontend.Variable) {
	assertRingMembership(api, inputs, outputs, ringProgramID, true)
}

// AssertRingMember — ring authority: every real utxo belongs to the signing
// ring, with no exemption, so value cannot leave the ring on this rail.
func AssertRingMember(api frontend.API, inputs []Input, outputs []UtxoCircuitFields, ringProgramID frontend.Variable) {
	assertRingMembership(api, inputs, outputs, ringProgramID, false)
}

func assertRingMembership(
	api frontend.API,
	inputs []Input,
	outputs []UtxoCircuitFields,
	ringProgramID frontend.Variable,
	allowDefaultRing bool,
) {
	for _, in := range inputs {
		AssertWhen(api, in.isUtxo(api), checkRingMembership(api, in.Utxo, ringProgramID, allowDefaultRing))
	}
	for _, utxo := range outputs {
		AssertWhen(api, utxo.isUtxo(api), checkRingMembership(api, utxo, ringProgramID, allowDefaultRing))
	}
}

// checkRingMembership returns 1 iff the utxo is owned by the signing ring.
// When allowDefaultRing is set, a default-ring utxo is also accepted, provided
// it has no ring data.
func checkRingMembership(
	api frontend.API,
	u UtxoCircuitFields,
	ringProgramID frontend.Variable,
	allowDefaultRing bool,
) frontend.Variable {
	isMemberOfSigningRing := api.IsZero(api.Sub(u.RingProgramID, ringProgramID))
	if !allowDefaultRing {
		return isMemberOfSigningRing
	}

	inCustomRing := api.Sub(1, api.IsZero(u.RingProgramID))
	dataSet := api.Sub(1, api.IsZero(u.RingDataHash))
	// If it is in custom ring it must be member of signing ring.
	ok := api.Select(inCustomRing, isMemberOfSigningRing, frontend.Variable(1))
	// Data must only be set if it is in custom ring.
	return api.Mul(ok, api.Select(dataSet, inCustomRing, frontend.Variable(1)))
}
