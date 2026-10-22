package merge_test

import (
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/merge"
	"github.com/helius-labs/zolana/prover/server/prover-test/refusal"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringkey"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringmerge"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func solve(t *testing.T, cs constraint.ConstraintSystem, c *merge.AnonymousMergeCircuit) error {
	t.Helper()
	witness, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	_, err = cs.Solve(witness)
	return err
}

func TestAnonymousMergeSolves(t *testing.T) {
	cs := ringkey.Compile(t, merge.NewAnonymousMergeCircuit(8))
	if err := solve(t, cs, ringmerge.Build(t, 8).Circuit); err != nil {
		t.Fatal(err)
	}
}

// Each case changes one value of an honest merge, rebinds the statement when the value is a
// statement element, and the named frames raise the refusal.
func TestAnonymousMergeRefusals(t *testing.T) {
	define := []string{"[assertIsEqual]", "merge.(*AnonymousMergeCircuit).Define"}
	dummy := []string{"shared.AssertWhen", "merge.(*AnonymousMergeCircuit).Define"}
	envelope := []string{"base.Envelope.Seal", "merge.(*AnonymousMergeCircuit).Define"}
	tests := []struct {
		name   string
		tamper func(*testing.T, *ringmerge.Statement)
		frames []string
	}{
		{"wrong owner", func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.OwnerKey[1] = 0
		}, define},
		{"wrong nullifier secret", func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.NullifierSecret = 20
		}, define},
		{"mixed assets", func(t *testing.T, s *ringmerge.Statement) {
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
		}, define},
		{"another merge's private tx hash", func(t *testing.T, s *ringmerge.Statement) {
			s.PrivateTxHash = new(big.Int).Add(s.PrivateTxHash, big.NewInt(1))
			s.Circuit.PrivateTxHash = s.PrivateTxHash
			s.Rebind(t)
		}, define},
		{"another merge's output", func(t *testing.T, s *ringmerge.Statement) {
			s.OutputHash = new(big.Int).Add(s.OutputHash, big.NewInt(1))
			s.Circuit.OutputUtxoHash = s.OutputHash
			s.Rebind(t)
		}, define},
		{"another merge's first nullifier", func(t *testing.T, s *ringmerge.Statement) {
			s.FirstNf = new(big.Int).Add(s.FirstNf, big.NewInt(1))
			s.Circuit.FirstNullifier = s.FirstNf
			s.Rebind(t)
		}, define},
		{"another ring", func(t *testing.T, s *ringmerge.Statement) {
			s.Circuit.RingProgramID = 0x5a0f
			s.Rebind(t)
		}, define},
		{"tampered disclosure field", func(t *testing.T, s *ringmerge.Statement) {
			s.Fields[0] = new(big.Int).Add(s.Fields[0], big.NewInt(1))
			s.Rebind(t)
		}, define},
		{"disclosure under another key", func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.DisclosureKey[0] = 0
		}, define},
		{"disclosure for another auditor", func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.AuditorPk[1] = 0
		}, define},
		{"disclosure key bytes outside 0..255 packing to the same key", func(_ *testing.T, s *ringmerge.Statement) {
			// Moving 256 between adjacent bytes keeps the pad key, the envelope's byte table refuses the encoding.
			key := &s.Circuit.DisclosureKey
			key[0], key[1] = key[0].(uint64)-1, key[1].(uint64)+256
		}, envelope},
		{"dummy first input", func(_ *testing.T, s *ringmerge.Statement) {
			// A well-formed dummy in slot zero, the slot SPP seeds every derived merge value from.
			s.Circuit.Inputs[0] = merge.Input{Domain: protocol.DummyDomain, TreeID: 0, Amount: 0, Blinding: s.Circuit.Inputs[0].Blinding, RingDataHash: 0}
		}, define},
		{"hidden input amount", func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.Inputs[1].Amount = 8
		}, define},
		{"padding with an amount", func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.Inputs[2].Amount = 1
		}, dummy},
		{"public hash of another statement", func(t *testing.T, s *ringmerge.Statement) {
			s.Circuit.PublicInputHash = 1
		}, define},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ringmerge.Build(t, 8)
			tt.tamper(t, s)
			refusal.Require(t, test.IsSolved(merge.NewAnonymousMergeCircuit(8), s.Circuit, ecc.BN254.ScalarField()), tt.frames...)
		})
	}
}

func TestAnonymousMergeRejectsUnsupportedWidth(t *testing.T) {
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, merge.NewAnonymousMergeCircuit(9)); err == nil {
		t.Fatal("compiled a width SPP has no merge key for")
	}
}

// Every shipped width holds its pin, every width SPP merges solves.
func TestAnonymousMergeCost(t *testing.T) {
	for _, n := range mergeshared.SupportedInputCounts {
		cs := ringkey.Compile(t, merge.NewAnonymousMergeCircuit(n))
		if slices.Contains(common.MergeAnonymousWidths, n) {
			ringkey.RequirePinned(t, ringkey.Name(t, common.RingAnonymousMerge, n, 0), cs)
		}
		if n == 8 {
			continue
		}
		if err := solve(t, cs, ringmerge.Build(t, n).Circuit); err != nil {
			t.Fatal(err)
		}
	}
}
