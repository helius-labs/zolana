package merge_chain

import (
	"math/big"
	"testing"

	"zolana/prover/circuits/gadget"
	mergeshared "zolana/prover/circuits/spp_merge/shared"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// mergePreimageCircuit folds a merge's public input the way the merge circuit
// does, out of the same shared code. Nothing else pins the eight fields the
// chain opens. One wrong field shifts every leg's binding to another value.
type mergePreimageCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	mergeshared.CommonPublicInputs
	UserSigningPkHash frontend.Variable
}

func (c *mergePreimageCircuit) Define(api frontend.API) error {
	fields := c.CommonPublicInputs.Prefix(api)
	fields = append(fields, c.UserSigningPkHash)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, fields))
	return nil
}

func TestLegPreimageMatchesTheMergePublicInput(t *testing.T) {
	assert := test.NewAssert(t)

	leg := Leg{
		OutputUtxoHash:   big.NewInt(4001),
		ExternalDataHash: big.NewInt(4002),
		AllowDummyInputs: big.NewInt(1),
		SigningPkHash:    big.NewInt(4003),
	}
	for i := 0; i < Slots; i++ {
		leg.Nullifiers[i] = big.NewInt(int64(100 + i))
		leg.UtxoTreeRoots[i] = big.NewInt(int64(200 + i))
		leg.NullifierTreeRoots[i] = big.NewInt(int64(300 + i))
		leg.InputUtxoHashes[i] = big.NewInt(int64(400 + i))
	}

	fields, err := leg.preimage()
	assert.NoError(err)
	folded, err := hashChain(fields[:])
	assert.NoError(err)

	assignment := &mergePreimageCircuit{
		PublicInputHash:    folded,
		CommonPublicInputs: mergeshared.NewCommonPublicInputs(),
		UserSigningPkHash:  leg.SigningPkHash,
	}
	assignment.OutputHash = leg.OutputUtxoHash
	assignment.ExternalDataHash = leg.ExternalDataHash
	assignment.AllowDummyInputs = leg.AllowDummyInputs
	privateTxHash, err := leg.privateTxHash()
	assert.NoError(err)
	assignment.PrivateTxHash = privateTxHash
	for i := 0; i < Slots; i++ {
		assignment.Nullifiers[i] = leg.Nullifiers[i]
		assignment.UtxoTreeRoots[i] = leg.UtxoTreeRoots[i]
		assignment.NullifierTreeRoots[i] = leg.NullifierTreeRoots[i]
	}

	assert.NoError(test.IsSolved(
		&mergePreimageCircuit{CommonPublicInputs: mergeshared.NewCommonPublicInputs()},
		assignment,
		ecc.BN254.ScalarField(),
	))
}
