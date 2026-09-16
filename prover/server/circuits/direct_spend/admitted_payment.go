package directspend

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction/shared"
)

type AdmittedPaymentCircuit struct {
	Certificate Certificate
	Balance     Balance

	PublicInputHash frontend.Variable `gnark:",public"`
}

func NewAdmittedPayment(inputs, outputs int) *AdmittedPaymentCircuit {
	return &AdmittedPaymentCircuit{
		Certificate: newCertificate(inputs),
		Balance:     NewBalance(1, outputs).Balance,
	}
}

func (c *AdmittedPaymentCircuit) Define(api frontend.API) error {
	compressor, err := gadget.NewGKRCompressor(api)
	if err != nil {
		return err
	}
	return c.constrain(api, compressor, c.Certificate.StateRoot, transaction.StateTreeHeight)
}

func (c *AdmittedPaymentCircuit) constrain(api frontend.API, compressor *gadget.GKRCompressor, membershipRoot frontend.Variable, height int) error {
	return c.constrainCertificate(api, func(certificate *Certificate) error {
		certificate.StateRoot = membershipRoot
		return certificate.constrainPaths(api, compressor, height)
	})
}

func (c *AdmittedPaymentCircuit) constrainCertificate(api frontend.API, constrain func(*Certificate) error) error {
	return c.constrainCertificateDomain(api, AdmittedPaymentDomain, constrain)
}

func (c *AdmittedPaymentCircuit) constrainCertificateDomain(api frontend.API, domain frontend.Variable, constrain func(*Certificate) error) error {
	if len(c.Balance.Values) != 1 {
		return fmt.Errorf("direct spend: inconsistent payment shape")
	}
	certificate := c.Certificate
	if err := constrain(&certificate); err != nil {
		return err
	}
	if err := c.Balance.constrain(api); err != nil {
		return err
	}
	bindCertificateBalance(api, &c.Certificate, &c.Balance)
	fields := []frontend.Variable{domain}
	fields = append(fields, c.Certificate.fields(api)...)
	fields = append(fields, c.Balance.fields(api)...)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, fields))
	return nil
}
