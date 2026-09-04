package shared_test

import (
	"testing"

	. "zolana/prover/circuits/spp_transaction/shared"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type txSecretDerivationCircuit struct {
	FirstNullifier             frontend.Variable
	TxSecret                   frontend.Variable
	ExpectedOutputBlindingSeed frontend.Variable
	ExpectedPrivateTxBlinding  frontend.Variable
}

func (c *txSecretDerivationCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(
		c.ExpectedOutputBlindingSeed,
		DeriveOutputBlindingSeed(api, c.FirstNullifier, c.TxSecret),
	)
	api.AssertIsEqual(
		c.ExpectedPrivateTxBlinding,
		DerivePrivateTxBlinding(api, c.FirstNullifier, c.TxSecret),
	)
	return nil
}

// TestTxSecretDerivationsMatchProtocol checks the circuit's two TxSecret
// children against the protocol package, which clients use to build the
// witness and the private_tx_hash they sign.
func TestTxSecretDerivationsMatchProtocol(t *testing.T) {
	firstNullifier, txSecret := spptest.Fe(7), spptest.Fe(42)
	seed, err := protocol.OutputBlindingSeed(firstNullifier, txSecret)
	seed = spptest.MustHash(t, seed, err)
	blinding, err := protocol.PrivateTxBlinding(firstNullifier, txSecret)
	blinding = spptest.MustHash(t, blinding, err)

	test.NewAssert(t).SolvingSucceeded(
		&txSecretDerivationCircuit{},
		&txSecretDerivationCircuit{
			FirstNullifier:             firstNullifier,
			TxSecret:                   txSecret,
			ExpectedOutputBlindingSeed: seed,
			ExpectedPrivateTxBlinding:  blinding,
		},
		test.WithCurves(ecc.BN254),
	)
}
