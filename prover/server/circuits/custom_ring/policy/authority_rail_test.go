package policy

import (
	"math/big"
	"testing"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
)

// Every UTXO inside the ring and the blinding derived as the rail derives it, the policy statement binds the rail's preimage unchanged.
func TestPolicyStatementBindsTheAuthorityRailPreimage(t *testing.T) {
	cs := testConstraintSystem(t)
	s := newStatement(t, defaultFixture())
	ring := big.NewInt(0x5a)
	for i := range s.inputs {
		if s.inputs[i].Domain.(*big.Int).Int64() == protocol.UtxoDomain {
			s.inputs[i].RingProgramID = ring
		}
	}
	for i := range s.outputs {
		if s.outputs[i].Domain.(*big.Int).Int64() == protocol.UtxoDomain {
			s.outputs[i].RingProgramID = ring
		}
	}
	spent := s.inputs[0]
	firstNullifier := spptest.MustNullifier(t, hostUtxoHash(t, spent), spent.Blinding.(*big.Int), big.NewInt(7))
	blinding, err := protocol.PrivateTxBlinding(firstNullifier, big.NewInt(4242))
	s.privateTxBlinding = spptest.MustHash(t, blinding, err)
	s.addressChain = spptest.MustHashChain(t, []*big.Int{big.NewInt(0), big.NewInt(0)})
	s.updateHashes(t)

	inputHashes := []*big.Int{hostUtxoHash(t, s.inputs[0]), big.NewInt(0)}
	outputHashes := []*big.Int{hostUtxoHash(t, s.outputs[0]), big.NewInt(0)}
	rail := spptest.MustPrivateTxHash(t, inputHashes, outputHashes, []*big.Int{big.NewInt(0), big.NewInt(0)}, s.externalDataHash, s.privateTxBlinding)
	if rail.Cmp(s.privateTxHash) != 0 {
		t.Fatalf("the policy preimage %s differs from the rail preimage %s", s.privateTxHash, rail)
	}

	solve(t, cs, s.assignment(t, defaultFixture().listFacts))
}
