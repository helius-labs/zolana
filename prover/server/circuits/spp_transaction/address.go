package transaction

import (
	gadgetlib "zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
)

// AddressGadget derives a program-owned address from the owning program, the
// address tree, and the program data seed:
//
//	address = Poseidon(AddressDomain, ProgramId, TreePubkey, seed)
//
// AddressDomain separates this preimage from the per-UTXO Domain tag. ProgramId
// is the program-identity field element -- the same single value bound to a
// program-owned UTXO's owner and exposed as the public ProgramID input -- so the
// address is namespaced per program with no separate program-id input. TreePubkey
// is sha256_be(address_tree_pubkey), a single field element (sha256_be zeroes the
// top byte, so the digest is < the BN254 modulus) computed off-circuit, which
// domain-separates the address per tree.
type AddressGadget struct {
	ProgramId  frontend.Variable
	TreePubkey frontend.Variable
	Seed       frontend.Variable
}

func (gadget AddressGadget) DefineGadget(api frontend.API) interface{} {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(AddressDomain),
		gadget.ProgramId,
		gadget.TreePubkey,
		gadget.Seed,
	})
}
