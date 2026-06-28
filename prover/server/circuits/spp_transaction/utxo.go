package transaction

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
	ProgramID     frontend.Variable
	ZoneDataHash  frontend.Variable
	ZoneProgramID frontend.Variable
}

// DefineGadget hashes the UTXO's fields into its commitment. This lets
// UtxoCircuitFields be used directly as a gadget via abstractor.Call, for both
// input (step 4.1) and output (step 5.1) utxo hashes.
func (u UtxoCircuitFields) DefineGadget(api frontend.API) interface{} {
	ownerUtxoHash := gadgetlib.PoseidonHash(api, []frontend.Variable{u.Owner, u.Blinding})
	programHash := gadgetlib.PoseidonHash(api, []frontend.Variable{u.DataHash, u.ProgramID})
	zoneHash := gadgetlib.PoseidonHash(api, []frontend.Variable{u.ZoneDataHash, u.ZoneProgramID})
	return gadgetlib.PoseidonHash(api, []frontend.Variable{
		u.Domain,
		u.Asset,
		u.Amount,
		programHash,
		zoneHash,
		ownerUtxoHash,
	})
}

func UtxoHashCircuit(api frontend.API, u UtxoCircuitFields) frontend.Variable {
	return abstractor.Call(api, u)
}

// OwnerHashGadget binds an owner key hash to a nullifier public key — the owner
// commitment verified in step 4.2.
type OwnerHashGadget struct {
	OwnerKeyHash frontend.Variable
	NullifierPk  frontend.Variable
}

func (gadget OwnerHashGadget) DefineGadget(api frontend.API) interface{} {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{gadget.OwnerKeyHash, gadget.NullifierPk})
}
