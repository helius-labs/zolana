package gnarksdk_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"zolana/gnarksdk"
	"zolana/prover/prover-test/spp/protocol"
)

type utxoCircuit struct {
	Utxo     gnarksdk.Utxo
	Expected frontend.Variable `gnark:",public"`
}

func (c *utxoCircuit) Define(api frontend.API) error {
	c.Utxo.AssertDefaultRing(api)
	api.AssertIsEqual(c.Utxo.Hash(api), c.Expected)
	return nil
}

func sampleUtxo() protocol.Utxo {
	return protocol.Utxo{
		Domain:        big.NewInt(protocol.UtxoDomain),
		Owner:         big.NewInt(11),
		Asset:         big.NewInt(13),
		Amount:        big.NewInt(25),
		Blinding:      big.NewInt(17),
		DataHash:      big.NewInt(19),
		RingDataHash:  new(big.Int),
		RingProgramID: new(big.Int),
	}
}

func utxoAssignment(t *testing.T, u protocol.Utxo, treeID int64) *utxoCircuit {
	t.Helper()
	return &utxoCircuit{
		Utxo: gnarksdk.Utxo{
			Domain:        u.Domain,
			Owner:         u.Owner,
			Asset:         u.Asset,
			Amount:        u.Amount,
			Blinding:      u.Blinding,
			DataHash:      u.DataHash,
			RingDataHash:  u.RingDataHash,
			RingProgramID: u.RingProgramID,
			TreeID:        treeID,
		},
		Expected: must(t)(protocol.UtxoHash(u, big.NewInt(treeID))),
	}
}

func TestUtxoHashMatchesProtocol(t *testing.T) {
	cs := compile(t, &utxoCircuit{})
	valid := utxoAssignment(t, sampleUtxo(), 2)
	assertAccepted(t, cs, valid)

	otherTree := utxoAssignment(t, sampleUtxo(), 3)
	otherTree.Expected = valid.Expected
	assertRejected(t, cs, otherTree)
}

func TestAssertDefaultRingRejectsRingAndNonUtxoDomains(t *testing.T) {
	cs := compile(t, &utxoCircuit{})
	for name, mutate := range map[string]func(*protocol.Utxo){
		"dummy domain":    func(u *protocol.Utxo) { u.Domain = big.NewInt(protocol.DummyDomain) },
		"address domain":  func(u *protocol.Utxo) { u.Domain = big.NewInt(protocol.AddressDomain) },
		"ring data hash":  func(u *protocol.Utxo) { u.RingDataHash = big.NewInt(1) },
		"ring program id": func(u *protocol.Utxo) { u.RingProgramID = big.NewInt(1) },
	} {
		t.Run(name, func(t *testing.T) {
			u := sampleUtxo()
			mutate(&u)
			assertRejected(t, cs, utxoAssignment(t, u, 2))
		})
	}
}
