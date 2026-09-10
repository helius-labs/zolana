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

// utxoHashGadget hashes a utxo under the raw u16 id of its tree, so equal
// utxos in different trees have distinct hashes, nullifiers, and addresses.
type utxoHashGadget struct {
	Domain        frontend.Variable
	TreeID        frontend.Variable
	Owner         frontend.Variable
	Asset         frontend.Variable
	Amount        frontend.Variable
	Blinding      frontend.Variable
	DataHash      frontend.Variable
	RingDataHash  frontend.Variable
	RingProgramID frontend.Variable
}

func (g utxoHashGadget) DefineGadget(api frontend.API) interface{} {
	ownerUtxoHash := gadgetlib.PoseidonHash(api, []frontend.Variable{g.Owner, g.Blinding})
	ringHash := gadgetlib.PoseidonHash(api, []frontend.Variable{g.RingDataHash, g.RingProgramID})
	return gadgetlib.PoseidonHash(api, []frontend.Variable{
		g.Domain,
		g.TreeID,
		g.Asset,
		g.Amount,
		g.DataHash,
		ringHash,
		ownerUtxoHash,
	})
}

// isUtxo: the slot carries a spendable or created utxo.
func (u UtxoCircuitFields) isUtxo(api frontend.API) frontend.Variable {
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

// assertInDefaultRing asserts the utxo is not a member of a ring.
func (u UtxoCircuitFields) assertInDefaultRing(api frontend.API) {
	api.AssertIsEqual(u.RingProgramID, 0)
	api.AssertIsEqual(u.RingDataHash, 0)
}

// CheckDummy returns 1 iff every field except the domain and blinding is zero,
// so the utxo carries nothing; the blinding stays free so dummy hashes are
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

// UtxoHashCircuit hashes a utxo under treeID: the public input tree id for
// inputs, the public output tree id for outputs.
func UtxoHashCircuit(api frontend.API, u UtxoCircuitFields, treeID frontend.Variable) frontend.Variable {
	return abstractor.Call(api, utxoHashGadget{
		Domain:        u.Domain,
		TreeID:        treeID,
		Owner:         u.Owner,
		Asset:         u.Asset,
		Amount:        u.Amount,
		Blinding:      u.Blinding,
		DataHash:      u.DataHash,
		RingDataHash:  u.RingDataHash,
		RingProgramID: u.RingProgramID,
	})
}

// ownerHashGadget binds an owner key hash to a nullifier public key — the owner
// commitment verified in step 3.3.
type ownerHashGadget struct {
	OwnerKeyHash frontend.Variable
	NullifierPk  frontend.Variable
}

func (gadget ownerHashGadget) DefineGadget(api frontend.API) interface{} {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{gadget.OwnerKeyHash, gadget.NullifierPk})
}
