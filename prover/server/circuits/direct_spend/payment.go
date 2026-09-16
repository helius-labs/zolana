package directspend

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

type PaymentCircuit struct {
	Certificate Certificate
	Freshness   Freshness
	Balance     Balance

	PublicInputHash frontend.Variable `gnark:",public"`
	GKR             bool              `gnark:"-" json:"-"`
	Transcript      string            `gnark:"-" json:"-"`
}

func NewPayment(inputs, outputs int) *PaymentCircuit {
	return &PaymentCircuit{
		Certificate: newCertificate(inputs), Freshness: NewFreshness(inputs).Freshness,
		Balance: NewBalance(1, outputs).Balance,
	}
}

func (c *PaymentCircuit) Define(api frontend.API) error {
	var compressor *gadget.GKRCompressor
	if c.GKR {
		var err error
		name := c.Transcript
		if name == "" {
			name = "POSEIDON2"
		}
		compressor, err = gadget.NewGKRCompressorWithTranscript(api, name)
		if err != nil {
			return err
		}
	}
	return c.constrain(api, compressor, compressor)
}

func (c *PaymentCircuit) constrain(api frontend.API, certificate, freshness *gadget.GKRCompressor) error {
	if len(c.Balance.Values) != 1 || len(c.Certificate.Nullifiers) != len(c.Freshness.Nullifiers) {
		return fmt.Errorf("direct spend: inconsistent payment shape")
	}
	if err := c.Certificate.constrainWithCompressor(api, certificate); err != nil {
		return err
	}
	if err := c.Freshness.constrainWithCompressor(api, freshness); err != nil {
		return err
	}
	if err := c.Balance.constrain(api); err != nil {
		return err
	}
	api.AssertIsEqual(c.Certificate.TreeID, c.Freshness.TreeID)
	api.AssertIsEqual(c.Certificate.Count, c.Freshness.Count)
	bindCertificateBalance(api, &c.Certificate, &c.Balance)
	for i, nullifier := range c.Certificate.Nullifiers {
		api.AssertIsEqual(nullifier, c.Freshness.Nullifiers[i])
	}
	fields := []frontend.Variable{PaymentDomain}
	fields = append(fields, c.Certificate.fields(api)...)
	fields = append(fields, c.Freshness.fields(api)...)
	fields = append(fields, c.Balance.fields(api)...)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, fields))
	return nil
}

func bindCertificateBalance(api frontend.API, certificate *Certificate, balance *Balance) {
	api.AssertIsEqual(certificate.Asset, balance.Asset)
	api.AssertIsEqual(certificate.ID, balance.Values[0].ID)
	api.AssertIsEqual(certificate.ValueCommitment, balance.Values[0].Commitment)
}
