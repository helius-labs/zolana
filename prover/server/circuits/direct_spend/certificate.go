package directspend

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction/shared"
)

const (
	MaxInputs         = 512
	MaxCertificates   = 16
	CertificateDomain = 0x44534331
	ValueDomain       = 0x44535631
	BalanceDomain     = 0x44534231
	FreshnessDomain   = 0x44534631
	PaymentDomain     = 0x44535031
)

type Note struct {
	Amount   frontend.Variable
	Blinding frontend.Variable
	Index    frontend.Variable
	Path     []frontend.Variable
}

type Certificate struct {
	ID              frontend.Variable
	TreeID          frontend.Variable
	StateRoot       frontend.Variable
	Owner           frontend.Variable
	Count           frontend.Variable
	Nullifiers      []frontend.Variable
	ValueCommitment frontend.Variable

	Asset           frontend.Variable
	ValueRandomness frontend.Variable
	NullifierSecret frontend.Variable
	Notes           []Note
}

type CertificateCircuit struct {
	Certificate
	PublicInputHash frontend.Variable `gnark:",public"`
}

func NewCertificate(n int) *CertificateCircuit {
	return &CertificateCircuit{Certificate: newCertificate(n)}
}

func newCertificate(n int) Certificate {
	c := Certificate{Nullifiers: make([]frontend.Variable, n), Notes: make([]Note, n)}
	for i := range c.Notes {
		c.Notes[i].Path = make([]frontend.Variable, transaction.StateTreeHeight)
	}
	return c
}

func (c *CertificateCircuit) Define(api frontend.API) error {
	if err := c.Certificate.constrain(api); err != nil {
		return err
	}
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.fields(api)))
	return nil
}

func (c *Certificate) constrain(api frontend.API) error {
	if len(c.Notes) == 0 || len(c.Notes) > MaxInputs || len(c.Nullifiers) != len(c.Notes) {
		return fmt.Errorf("direct spend: invalid input shape")
	}
	api.ToBinary(c.TreeID, 16)
	api.AssertIsDifferent(c.Asset, 0)
	api.AssertIsDifferent(c.Count, 0)
	owner := gadget.PoseidonHash(api, []frontend.Variable{
		c.Owner, gadget.PoseidonHash(api, []frontend.Variable{c.NullifierSecret}),
	})
	count, total, previous := frontend.Variable(0), frontend.Variable(0), frontend.Variable(1)
	for i, note := range c.Notes {
		if len(note.Path) != transaction.StateTreeHeight {
			return fmt.Errorf("direct spend: invalid note path %d", i)
		}
		active := api.Sub(1, api.IsZero(c.Nullifiers[i]))
		api.AssertIsEqual(api.Mul(active, api.Sub(1, previous)), 0)
		previous = active
		count = api.Add(count, active)
		api.ToBinary(note.Amount, 64)
		api.AssertIsEqual(api.Mul(api.Sub(1, active), note.Amount), 0)
		total = api.Add(total, note.Amount)
		hash := transaction.UtxoHashCircuit(api, plainNote(owner, c.Asset, note.Amount, note.Blinding), c.TreeID)
		root := abstractor.Call(api, gadget.MerkleRootGadget{
			Hash: hash, Index: api.ToBinary(note.Index, transaction.StateTreeHeight),
			Path: note.Path, Height: transaction.StateTreeHeight,
		})
		api.AssertIsEqual(api.Mul(active, api.Sub(root, c.StateRoot)), 0)
		nullifier := abstractor.Call(api, transaction.NullifierGadget{
			UtxoHash: hash, Blinding: note.Blinding, NullifierSecret: c.NullifierSecret,
		})
		api.AssertIsEqual(c.Nullifiers[i], api.Mul(active, nullifier))
	}
	api.AssertIsEqual(c.Count, count)
	api.AssertIsEqual(c.ValueCommitment, valueCommitment(api, c.ID, c.Asset, total, c.ValueRandomness))
	return nil
}

func (c *Certificate) fields(api frontend.API) []frontend.Variable {
	return []frontend.Variable{
		CertificateDomain, c.ID, c.TreeID, c.StateRoot, c.Owner, c.Count,
		gadget.HashChain4(api, c.Nullifiers), c.ValueCommitment,
	}
}

func valueCommitment(api frontend.API, id, asset, value, randomness frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{ValueDomain, id, asset, value, randomness})
}

func plainNote(owner, asset, amount, blinding frontend.Variable) transaction.UtxoCircuitFields {
	return transaction.UtxoCircuitFields{
		Domain: transaction.UtxoDomain, Owner: owner, Asset: asset, Amount: amount,
		Blinding: blinding, DataHash: 0, RingDataHash: 0, RingProgramID: 0,
	}
}
