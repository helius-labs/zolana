package base

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"zolana/prover/circuits/gadget"
	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/circuits/verifiable-encryption/p256"
)

const AuditEncInfo = "CRING/adt1"

var SharedSecretTag = []byte("CR_S")

type CustomRingBaseCircuit struct {
	PublicInputHash     frontend.Variable `gnark:",public"`
	PrivateTxHash       frontend.Variable
	TxViewingSk         [32]frontend.Variable
	EphSk               [32]frontend.Variable
	AuditorPk           [65]frontend.Variable
	Salt                [16]frontend.Variable
	Outputs             [AuditOutputSlots]AuditOutputWires
	OutputCountSelected [AuditOutputSlots]frontend.Variable
}

type AuditBlockWires struct {
	PrivateTxHash       frontend.Variable
	TxViewingSk         [32]frontend.Variable
	EphSk               [32]frontend.Variable
	AuditorPk           [65]frontend.Variable
	Salt                [16]frontend.Variable
	Outputs             [AuditOutputSlots]AuditOutputWires
	OutputCountSelected [AuditOutputSlots]frontend.Variable
}

func (c *CustomRingBaseCircuit) Define(api frontend.API) error {
	elements := DefineAuditBlock(api, AuditBlockWires{
		PrivateTxHash:       c.PrivateTxHash,
		TxViewingSk:         c.TxViewingSk,
		EphSk:               c.EphSk,
		AuditorPk:           c.AuditorPk,
		Salt:                c.Salt,
		Outputs:             c.Outputs,
		OutputCountSelected: c.OutputCountSelected,
	})
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, elements[:]))
	return nil
}

func DefineAuditBlock(api frontend.API, w AuditBlockWires) [11]frontend.Variable {
	rangeChecker := rangecheck.New(api)
	for _, b := range w.TxViewingSk {
		rangeChecker.Check(b, 8)
	}
	for _, b := range w.EphSk {
		rangeChecker.Check(b, 8)
	}
	txLo, txHi := p256.PublicKeyPacked(api, w.TxViewingSk)

	encrypted := ve.Envelope{
		SecretTag:   SharedSecretTag,
		KdfInfo:     []byte(AuditEncInfo),
		EphemeralSk: w.EphSk,
		RecipientPk: w.AuditorPk,
		Plaintext:   w.TxViewingSk[:],
	}.Encrypt(api)
	ciphertextHash := gadget.HashBytes(api, encrypted.Ciphertext)
	outputHashChain, disclosureHash := disclosureElements(
		api, rangeChecker, w.TxViewingSk, w.Salt, w.Outputs, w.OutputCountSelected,
	)
	saltField := gadget.PackBytesBE(api, w.Salt[:])[0]

	return [11]frontend.Variable{
		w.PrivateTxHash,
		txLo, txHi,
		encrypted.RecipientLo, encrypted.RecipientHi,
		encrypted.EphemeralLo, encrypted.EphemeralHi,
		ciphertextHash,
		outputHashChain,
		saltField,
		disclosureHash,
	}
}
