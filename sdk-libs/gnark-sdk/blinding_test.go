package gnarksdk_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"zolana/gnarksdk"
	"zolana/prover/prover-test/spp/protocol"
)

type blindingsCircuit struct {
	FirstNullifier    frontend.Variable `gnark:",public"`
	BlindingSeed      frontend.Variable
	PrivateTxBlinding frontend.Variable
	OutputBlindings   [3]frontend.Variable
}

func (c *blindingsCircuit) Define(api frontend.API) error {
	gnarksdk.AssertTransactionBlindings(api, c.FirstNullifier, c.BlindingSeed, c.PrivateTxBlinding, c.OutputBlindings[:]...)
	return nil
}

func TestAssertTransactionBlindingsMatchesProtocol(t *testing.T) {
	firstNullifier := big.NewInt(19)
	blindingSeed := big.NewInt(17)
	seed := must(t)(protocol.OutputBlindingSeed(firstNullifier, blindingSeed))
	valid := blindingsCircuit{
		FirstNullifier:    firstNullifier,
		BlindingSeed:      blindingSeed,
		PrivateTxBlinding: must(t)(protocol.PrivateTxBlinding(firstNullifier, blindingSeed)),
	}
	for i := range valid.OutputBlindings {
		valid.OutputBlindings[i] = must(t)(protocol.OutputBlinding(firstNullifier, seed, i))
	}
	cs := compile(t, &blindingsCircuit{})
	assertAccepted(t, cs, &valid)

	bad := valid
	bad.FirstNullifier = plusOne(firstNullifier)
	assertRejected(t, cs, &bad)

	bad = valid
	bad.PrivateTxBlinding = seed
	assertRejected(t, cs, &bad)

	for i := range valid.OutputBlindings {
		bad = valid
		bad.OutputBlindings[i] = valid.OutputBlindings[(i+1)%len(valid.OutputBlindings)]
		assertRejected(t, cs, &bad)
	}
}
