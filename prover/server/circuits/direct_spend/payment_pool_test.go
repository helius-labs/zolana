package directspend

import (
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/prover/circuits/gadget"
)

type splitPoolPayment PaymentCircuit

func (c *splitPoolPayment) Define(api frontend.API) error {
	certificate, err := gadget.NewGKRCompressor(api)
	if err != nil {
		return err
	}
	freshness, err := gadget.NewGKRCompressor(api)
	if err != nil {
		return err
	}
	return (*PaymentCircuit)(c).constrain(api, certificate, freshness)
}

func TestGKRPoolPartition(t *testing.T) {
	if os.Getenv("GKR_POOL_COMPILE") == "" {
		t.Skip("set GKR_POOL_COMPILE to compare shared and split GKR pools")
	}
	for _, inputs := range []int{144, 512} {
		for _, split := range []bool{false, true} {
			payment := NewPayment(inputs, 2)
			payment.GKR = true
			var circuit frontend.Circuit = payment
			if split {
				circuit = (*splitPoolPayment)(payment)
			}
			start := time.Now()
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("GKR_POOL_COMPILE inputs=%d split=%t constraints=%d compile_ms=%d", inputs, split, cs.GetNbConstraints(), time.Since(start).Milliseconds())
		}
	}
}
