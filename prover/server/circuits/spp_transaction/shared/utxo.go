package shared

import (
	gadgetlib "zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

type UtxoCircuitFields struct {
	Domain        frontend.Variable
	Owner         frontend.Variable
	Asset         frontend.Variable
	Amount        frontend.Variable
	Blinding      frontend.Variable
	DataHash      frontend.Variable
	RingDataHash  frontend.Variable
	RingProgramID frontend.Variable
}

func (u UtxoCircuitFields) DefineGadget(api frontend.API) interface{} {
	ownerUtxoHash := gadgetlib.PoseidonHash(api, []frontend.Variable{u.Owner, u.Blinding})
	ringHash := gadgetlib.PoseidonHash(api, []frontend.Variable{u.RingDataHash, u.RingProgramID})
	return gadgetlib.PoseidonHash(api, []frontend.Variable{
		u.Domain,
		u.Asset,
		u.Amount,
		u.DataHash,
		ringHash,
		ownerUtxoHash,
	})
}

// isUtxo is 1 when the slot carries a spendable or created utxo.
func (u UtxoCircuitFields) isUtxo(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(u.Domain, UtxoDomain))
}

// isAddress is 1 when the slot creates an address.
func (u UtxoCircuitFields) isAddress(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(u.Domain, AddressDomain))
}

// isDummy is 1 when the slot is padding and carries nothing.
func (u UtxoCircuitFields) isDummy(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(u.Domain, DummyDomain))
}

// isUtxoOrAddress is 1 when the slot carries a spendable or an address utxo.
func (u UtxoCircuitFields) isUtxoOrAddress(api frontend.API) frontend.Variable {
	return api.Sub(1, u.isDummy(api))
}

// assertInDefaultRing asserts the utxo is not a member of a ring.
func (u UtxoCircuitFields) assertInDefaultRing(api frontend.API) {
	api.AssertIsEqual(u.RingProgramID, 0)
	api.AssertIsEqual(u.RingDataHash, 0)
}

// CheckDummy returns 1 iff every field except the domain and blinding is zero,
// so the utxo carries nothing. The blinding stays free so dummy hashes are
// indistinguishable from real UTXO hashes.
func (u UtxoCircuitFields) CheckDummy(api frontend.API) frontend.Variable {
	return allZero(api,
		u.Owner,
		u.Asset,
		u.Amount,
		u.DataHash,
		u.RingDataHash,
		u.RingProgramID,
	)
}

func UtxoHashCircuit(api frontend.API, u UtxoCircuitFields) frontend.Variable {
	return abstractor.Call(api, u)
}

// OwnerHashGadget binds an owner key hash to a nullifier public key, the
// owner commitment the input ownership check verifies.
type OwnerHashGadget struct {
	OwnerKeyHash frontend.Variable
	NullifierPk  frontend.Variable
}

func (gadget OwnerHashGadget) DefineGadget(api frontend.API) interface{} {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{gadget.OwnerKeyHash, gadget.NullifierPk})
}
