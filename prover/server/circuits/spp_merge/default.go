package merge

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
	ve "zolana/prover/circuits/verifiable-encryption"
)

type (
	Input  = mergeshared.Input
	Output = mergeshared.Output
)

const (
	UtxoDomain  = mergeshared.UtxoDomain
	DummyDomain = mergeshared.DummyDomain
)

type Circuit struct {
	NumInputs int `gnark:"-"`

	Inputs []Input
	Output Output

	MintChunks [mergeshared.MintChunkCount]frontend.Variable

	OwnerPkHash         frontend.Variable
	UserNullifierPk     frontend.Variable
	UserNullifierSecret frontend.Variable

	ViewingPk   [ve.UncompressedPointBytes]frontend.Variable
	EphemeralSk [ve.ScalarBytes]frontend.Variable

	mergeshared.CommonPublicInputs

	UserSigningPkHash frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

func NewMergeCircuit(n int) *Circuit {
	return &Circuit{
		NumInputs:          n,
		Inputs:             mergeshared.NewInputs(n),
		CommonPublicInputs: mergeshared.NewCommonPublicInputs(n),
	}
}

func (c *Circuit) Define(api frontend.API) error {
	var encrypted ve.Encrypted
	tx := mergeshared.Transaction{
		Inputs:              c.Inputs,
		Output:              c.Output,
		MintChunks:          c.MintChunks,
		OwnerPkHash:         c.OwnerPkHash,
		UserNullifierPk:     c.UserNullifierPk,
		UserNullifierSecret: c.UserNullifierSecret,
		Public:              c.CommonPublicInputs,
		RingProgramID:       frontend.Variable(0),
		OutputBlinding: func(amount frontend.Variable) frontend.Variable {
			encrypted = ve.Envelope{
				SecretTag:   mergeshared.MergeSecretTag,
				KdfInfo:     mergeshared.MergeKdfInfo,
				EphemeralSk: c.EphemeralSk,
				RecipientPk: c.ViewingPk,
				Plaintext:   mergeshared.MergePlaintext(api, amount, c.MintChunks),
			}.Encrypt(api)
			return mergeshared.MergeDerivedBlinding(api, encrypted.SharedSecret)
		},
	}
	if err := tx.ValidateLayout(c.NumInputs); err != nil {
		return err
	}

	assertDefaultRing(api, tx.Inputs, tx.Output)
	tx.Constrain(api)
	api.AssertIsEqual(c.UserSigningPkHash, c.OwnerPkHash)

	envelope := mergeshared.EnvelopePublicElements(api, encrypted)
	fields := c.CommonPublicInputs.Prefix(api)
	fields = append(fields, c.UserSigningPkHash, c.UserNullifierPk)
	fields = append(fields, envelope[:]...)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, fields))
	return nil
}

func assertDefaultRing(api frontend.API, inputs []Input, output Output) {
	for _, input := range inputs {
		isUtxo := api.IsZero(api.Sub(input.Domain, UtxoDomain))
		abstractor.CallVoid(api, gadget.AssertZeroWhen{
			Cond: isUtxo,
			V:    input.RingDataHash,
		})
	}
	api.AssertIsEqual(output.RingDataHash, 0)
}
