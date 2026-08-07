package squadszone

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	squadsutils "zolana/prover/circuits/squads/utils"
	"zolana/prover/prover-test/poseidon"
)

type proposalConstraintCircuit struct {
	Proposal       Proposal
	Transaction    squadsutils.Transaction
	RecipientOwner frontend.Variable
	Expected       frontend.Variable `gnark:",public"`
}

func newProposalConstraintCircuit() *proposalConstraintCircuit {
	return &proposalConstraintCircuit{
		Transaction: squadsutils.Transaction{
			Inputs:  make([]squadsutils.Utxo, 1),
			Outputs: make([]squadsutils.Utxo, 2),
		},
	}
}

func (c *proposalConstraintCircuit) Define(api frontend.API) error {
	got := c.Proposal.Constrain(
		api,
		c.Transaction,
		nil,
		RecipientOutputIndex,
		true,
		c.RecipientOwner,
		0,
		1,
	)
	api.AssertIsEqual(got, c.Expected)
	return nil
}

func proposalConstraintWitness(t *testing.T) *proposalConstraintCircuit {
	t.Helper()
	asset := big.NewInt(11)
	recipientOwner := big.NewInt(12)
	recipientNullifier := big.NewInt(13)
	recipientHash, err := poseidon.Hash([]*big.Int{recipientOwner, recipientNullifier})
	if err != nil {
		t.Fatal(err)
	}
	amount := big.NewInt(14)
	blinding := big.NewInt(15)
	operation := big.NewInt(proposalTransfer)
	privateCore, err := poseidon.Hash([]*big.Int{
		proposalCoreV2Domain,
		operation,
		amount,
		recipientHash,
		blinding,
		big.NewInt(0),
	})
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := poseidon.Hash([]*big.Int{
		proposalV2Domain,
		operation,
		privateCore,
		asset,
		recipientOwner,
	})
	if err != nil {
		t.Fatal(err)
	}

	witness := newProposalConstraintCircuit()
	zeroUtxo := func() squadsutils.Utxo {
		return squadsutils.Utxo{
			OwnerHash:       big.NewInt(0),
			Asset:           big.NewInt(0),
			Amount:          big.NewInt(0),
			Blinding:        big.NewInt(0),
			ProgramDataHash: big.NewInt(0),
			RingDataHash:    big.NewInt(0),
			RingProgramID:   big.NewInt(0),
		}
	}
	witness.Transaction.Inputs[0] = zeroUtxo()
	witness.Transaction.Outputs[0] = zeroUtxo()
	witness.Transaction.Outputs[1] = zeroUtxo()
	witness.Transaction.ExternalDataHash = big.NewInt(0)
	witness.Proposal = Proposal{
		Amount:       amount,
		Recipient:    recipientHash,
		Asset:        asset,
		Destination:  recipientOwner,
		Blinding:     blinding,
		PublicAmount: big.NewInt(0),
	}
	witness.Transaction.Inputs[0].Asset = asset
	witness.Transaction.Outputs[0].Asset = asset
	witness.Transaction.Outputs[1].Asset = asset
	witness.Transaction.Outputs[1].OwnerHash = recipientHash
	witness.Transaction.Outputs[1].Amount = amount
	witness.RecipientOwner = recipientOwner
	witness.Expected = commitment
	return witness
}

func TestProposalRejectsAssetSubstitution(t *testing.T) {
	witness := proposalConstraintWitness(t)
	witness.Transaction.Outputs[1].Asset = big.NewInt(99)
	if err := test.IsSolved(newProposalConstraintCircuit(), witness, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected proposal asset substitution to violate constraints")
	}
}

func TestProposalRejectsTransferDestinationSubstitution(t *testing.T) {
	witness := proposalConstraintWitness(t)
	witness.RecipientOwner = big.NewInt(99)
	if err := test.IsSolved(newProposalConstraintCircuit(), witness, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected proposal recipient substitution to violate constraints")
	}
}
