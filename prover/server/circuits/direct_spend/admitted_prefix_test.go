package directspend

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/iden3/go-iden3-crypto/poseidon"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/transcript"
)

type PrefixAdmittedPayment struct {
	AdmittedPaymentCircuit
	PrefixRoot frontend.Variable
	Height     int    `gnark:"-"`
	Transcript string `gnark:"-"`
}

func NewPrefixAdmittedPayment(inputs, height int, transcript string) *PrefixAdmittedPayment {
	c := &PrefixAdmittedPayment{
		AdmittedPaymentCircuit: *NewAdmittedPayment(inputs, 2),
		Height:                 height,
		Transcript:             transcript,
	}
	for i := range c.Certificate.Notes {
		c.Certificate.Notes[i].Path = make([]frontend.Variable, height)
	}
	return c
}

func (c *PrefixAdmittedPayment) Define(api frontend.API) error {
	if c.Height < 1 || c.Height > 32 {
		return fmt.Errorf("invalid prefix shape")
	}
	compressor, err := gadget.NewGKRCompressorWithTranscript(api, c.Transcript)
	if err != nil {
		return err
	}
	if err := c.AdmittedPaymentCircuit.constrain(api, compressor, c.PrefixRoot, c.Height); err != nil {
		return err
	}
	root := c.PrefixRoot
	empty, err := emptyStateRoots()
	if err != nil {
		return err
	}
	for level := c.Height; level < 32; level++ {
		root = compressor.Compress(root, empty[level])
	}
	api.AssertIsEqual(root, c.Certificate.StateRoot)
	return nil
}

func emptyStateRoots() ([]*big.Int, error) {
	result := make([]*big.Int, 32)
	result[0] = new(big.Int)
	for i := 1; i < len(result); i++ {
		var err error
		result[i], err = poseidon.Hash([]*big.Int{result[i-1], result[i-1]})
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func TestAdmittedPrefixConstraints(t *testing.T) {
	if os.Getenv("ADMITTED_PREFIX_COUNTS") == "" {
		t.Skip("set ADMITTED_PREFIX_COUNTS=1")
	}
	transcript.Register()
	for _, height := range []int{10, 16, 20, 32} {
		for _, name := range []string{"POSEIDON2", transcript.NameForWidth(12)} {
			t.Run(fmt.Sprintf("%d/%s", height, name), func(t *testing.T) {
				cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, NewPrefixAdmittedPayment(512, height, name), frontend.WithCompressThreshold(300))
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("ADMITTED_PREFIX inputs=512 height=%d transcript=%s constraints=%d fft_domain=%d", height, name, cs.GetNbConstraints(), ecc.NextPowerOfTwo(uint64(cs.GetNbConstraints())))
			})
		}
	}
}
