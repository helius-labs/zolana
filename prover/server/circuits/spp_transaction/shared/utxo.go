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
	ZoneDataHash  frontend.Variable
	ZoneProgramID frontend.Variable
}

func (u UtxoCircuitFields) DefineGadget(api frontend.API) interface{} {
	ownerUtxoHash := gadgetlib.PoseidonHash(api, []frontend.Variable{u.Owner, u.Blinding})
	zoneHash := gadgetlib.PoseidonHash(api, []frontend.Variable{u.ZoneDataHash, u.ZoneProgramID})
	return gadgetlib.PoseidonHash(api, []frontend.Variable{
		u.Domain,
		u.Asset,
		u.Amount,
		u.DataHash,
		zoneHash,
		ownerUtxoHash,
	})
}

// IsUtxo: the slot carries a spendable or created utxo.
func (u UtxoCircuitFields) IsUtxo(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(u.Domain, UtxoDomain))
}

// isAddress: the slot creates an address.
func (u UtxoCircuitFields) isAddress(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(u.Domain, AddressDomain))
}

// isDummy: the slot is padding and carries nothing.
func (u UtxoCircuitFields) isDummy(api frontend.API) frontend.Variable {
	return api.IsZero(api.Sub(u.Domain, DummyDomain))
}

// isUtxoOrAddress: the slot carries content — a spendable or an address utxo.
func (u UtxoCircuitFields) isUtxoOrAddress(api frontend.API) frontend.Variable {
	return api.Sub(1, u.isDummy(api))
}

// AssertInDefaultZone asserts the utxo is not a member of a zone.
func (u UtxoCircuitFields) AssertInDefaultZone(api frontend.API) {
	api.AssertIsEqual(u.ZoneDataHash, u.ZoneProgramID)
	api.AssertIsEqual(u.ZoneDataHash, 0)
}

// checkDummy returns 1 iff every field except the domain and blinding is zero,
// so the utxo carries nothing; the blinding stays free so dummy hashes are
// indistinguishable from real ones.
func (u UtxoCircuitFields) checkDummy(api frontend.API) frontend.Variable {
	return allZero(api,
		u.Owner,
		u.Asset,
		u.Amount,
		u.DataHash,
		u.ZoneDataHash,
		u.ZoneProgramID,
	)
}

func UtxoHashCircuit(api frontend.API, u UtxoCircuitFields) frontend.Variable {
	return abstractor.Call(api, u)
}

// OwnerHashGadget binds an owner key hash to a nullifier public key — the owner
// commitment verified in step 3.3.
type OwnerHashGadget struct {
	OwnerKeyHash frontend.Variable
	NullifierPk  frontend.Variable
}

func (gadget OwnerHashGadget) DefineGadget(api frontend.API) interface{} {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{gadget.OwnerKeyHash, gadget.NullifierPk})
}
