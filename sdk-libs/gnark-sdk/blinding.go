package gnarksdk

import (
	"github.com/consensys/gnark/frontend"

	spp "zolana/prover/circuits/spp_transaction/shared"
)

// AssertTransactionBlindings asserts privateTxBlinding and the output
// blindings are the ones derived from firstNullifier and blindingSeed.
// outputBlindings[i] is the blinding of output slot i, counted after padding.
// The first nullifier enters the nullifier tree once, so the derived values
// are unique to one accepted transaction even when a seed is reused.
func AssertTransactionBlindings(api frontend.API, firstNullifier, blindingSeed, privateTxBlinding frontend.Variable, outputBlindings ...frontend.Variable) {
	seed := spp.DeriveOutputBlindingSeed(api, firstNullifier, blindingSeed)
	api.AssertIsEqual(privateTxBlinding, spp.DerivePrivateTxBlinding(api, firstNullifier, blindingSeed))
	for i, blinding := range outputBlindings {
		api.AssertIsEqual(blinding, spp.DeriveOutputBlinding(api, firstNullifier, seed, i))
	}
}
