package shared_test

import (
	"testing"

	. "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"

	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type blindingSeedDerivationCircuit struct {
	FirstNullifier             frontend.Variable
	BlindingSeed               frontend.Variable
	ExpectedOutputBlindingSeed frontend.Variable
	ExpectedPrivateTxBlinding  frontend.Variable
}

func (c *blindingSeedDerivationCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(
		c.ExpectedOutputBlindingSeed,
		DeriveOutputBlindingSeed(api, c.FirstNullifier, c.BlindingSeed),
	)
	api.AssertIsEqual(
		c.ExpectedPrivateTxBlinding,
		DerivePrivateTxBlinding(api, c.FirstNullifier, c.BlindingSeed),
	)
	return nil
}

// TestBlindingSeedDerivationsMatchProtocol checks the circuit's two BlindingSeed
// children against the protocol package, which clients use to build the
// witness and the private_tx_hash they sign.
func TestBlindingSeedDerivationsMatchProtocol(t *testing.T) {
	firstNullifier, blindingSeed := spptest.Fe(7), spptest.Fe(42)
	seed, err := protocol.OutputBlindingSeed(firstNullifier, blindingSeed)
	seed = spptest.MustHash(t, seed, err)
	blinding, err := protocol.PrivateTxBlinding(firstNullifier, blindingSeed)
	blinding = spptest.MustHash(t, blinding, err)

	test.NewAssert(t).SolvingSucceeded(
		&blindingSeedDerivationCircuit{},
		&blindingSeedDerivationCircuit{
			FirstNullifier:             firstNullifier,
			BlindingSeed:               blindingSeed,
			ExpectedOutputBlindingSeed: seed,
			ExpectedPrivateTxBlinding:  blinding,
		},
		test.WithCurves(ecc.BN254),
	)
}
