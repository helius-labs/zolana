package merge_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/merge"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringmerge"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func compile(t *testing.T, n int) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, merge.New(n), frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func solve(t *testing.T, cs constraint.ConstraintSystem, c *merge.Circuit) error {
	t.Helper()
	witness, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	_, err = cs.Solve(witness)
	return err
}

func TestAnonymousMergeSolves(t *testing.T) {
	cs := compile(t, 8)
	if err := solve(t, cs, ringmerge.Build(t, 8).Circuit); err != nil {
		t.Fatal(err)
	}
}

func TestAnonymousMergeRefusals(t *testing.T) {
	cs := compile(t, 8)
	for name, tamper := range map[string]func(*testing.T, *ringmerge.Statement){
		"wrong owner": func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.OwnerKey[1] = 0
		},
		"wrong nullifier secret": func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.NullifierSecret = 20
		},
		"mixed assets": func(t *testing.T, s *ringmerge.Statement) {
			// SPP would commit input one under another mint, the statement names that merge.
			must := ringmerge.MustOf(t)
			other := s.Mint
			other[0] ^= 1
			utxo := protocol.Utxo{
				Domain: big.NewInt(protocol.UtxoDomain),
				Owner:  must(protocol.OwnerHash(s.OwnerPkHash, s.NullifierPk)),
				Asset:  must(protocol.AssetField(other)), Amount: s.Amounts[1],
				Blinding: spptest.AsBigInt(s.Circuit.Inputs[1].Blinding), DataHash: big.NewInt(0),
				RingDataHash:  spptest.AsBigInt(s.Circuit.Inputs[1].RingDataHash),
				RingProgramID: spptest.AsBigInt(s.Circuit.RingProgramID),
			}
			hashes := append([]*big.Int{}, s.InputHashes...)
			hashes[1] = spptest.MustUtxoHash(t, utxo, big.NewInt(ringmerge.InputTreeID))
			s.PrivateTxHash = s.PrivateTx(t, hashes)
			s.Circuit.PrivateTxHash = s.PrivateTxHash
			s.Rebind(t)
		},
		"non-member": func(t *testing.T, s *ringmerge.Statement) {
			others := spptest.NewMemberRegistry(t, registry.Height)
			others.Update(t, big.NewInt(3), big.NewInt(0), big.NewInt(0))
			s.Circuit.MemberRegistryRoot = others.Root()
			s.Rebind(t)
		},
		"record of another registry": func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.MemberRecord.EscrowKey = 1
		},
		"another merge's private tx hash": func(t *testing.T, s *ringmerge.Statement) {
			s.PrivateTxHash = new(big.Int).Add(s.PrivateTxHash, big.NewInt(1))
			s.Circuit.PrivateTxHash = s.PrivateTxHash
			s.Rebind(t)
		},
		"another merge's output": func(t *testing.T, s *ringmerge.Statement) {
			s.OutputHash = new(big.Int).Add(s.OutputHash, big.NewInt(1))
			s.Circuit.OutputUtxoHash = s.OutputHash
			s.Rebind(t)
		},
		"another merge's first nullifier": func(t *testing.T, s *ringmerge.Statement) {
			s.FirstNf = new(big.Int).Add(s.FirstNf, big.NewInt(1))
			s.Circuit.FirstNullifier = s.FirstNf
			s.Rebind(t)
		},
		"another ring": func(t *testing.T, s *ringmerge.Statement) {
			s.Circuit.RingProgramID = 0x5a0f
			s.Rebind(t)
		},
		"tampered disclosure field": func(t *testing.T, s *ringmerge.Statement) {
			s.Fields[0] = new(big.Int).Add(s.Fields[0], big.NewInt(1))
			s.Rebind(t)
		},
		"disclosure under another key": func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.DisclosureKey[0] = 0
		},
		"disclosure for another auditor": func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.AuditorPk[1] = 0
		},
		"dummy first input": func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.Inputs[0].Domain = protocol.DummyDomain
		},
		"hidden input amount": func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.Inputs[1].Amount = 8
		},
		"padding with an amount": func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.Inputs[2].Amount = 1
		},
		"public hash of another statement": func(t *testing.T, s *ringmerge.Statement) {
			s.Circuit.PublicInputHash = 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := ringmerge.Build(t, 8)
			tamper(t, s)
			if solve(t, cs, s.Circuit) == nil {
				t.Fatal("tampered anonymous merge solved")
			}
		})
	}
}

func TestAnonymousMergeRejectsUnsupportedWidth(t *testing.T) {
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, merge.New(9)); err == nil {
		t.Fatal("compiled a width SPP has no merge key for")
	}
}

func TestAnonymousMergeCost(t *testing.T) {
	pinned := map[int]int{8: 62500, 24: 89046, 52: 135178}
	for _, n := range mergeshared.SupportedInputCounts {
		cs := compile(t, n)
		if got := cs.GetNbConstraints(); got != pinned[n] {
			t.Errorf("custom-ring-merge-anonymous-%d constraints=%d, pinned %d", n, got, pinned[n])
		}
		if n == 8 {
			continue
		}
		if err := solve(t, cs, ringmerge.Build(t, n).Circuit); err != nil {
			t.Fatal(err)
		}
	}
}
