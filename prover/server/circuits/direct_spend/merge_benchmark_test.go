package directspend_test

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	merge "zolana/prover/circuits/spp_merge"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
	transaction "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover/common"
)

func TestMergePaymentProving(t *testing.T) {
	dir := os.Getenv("COMPACT_MERGE_KEYS")
	if dir == "" {
		t.Skip("set COMPACT_MERGE_KEYS to existing merge keys")
	}
	for _, n := range []int{8, 36} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			system, err := common.ReadSystemFromFile(filepath.Join(dir, fmt.Sprintf("merge_%d_1.key", n)))
			if err != nil {
				t.Fatal(err)
			}
			ps := system.(*common.TransferProofSystem)
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, merge.NewMergeCircuit(n), frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			if constraintDigest(t, ccs) != constraintDigest(t, ps.ConstraintSystem) {
				t.Fatal("merge key circuit mismatch")
			}
			provePayment(t, "merge", n, 1, ps.ConstraintSystem, ps.ProvingKey, ps.VerifyingKey, mergeWitness(t, n))
		})
	}
}

func mergeWitness(t *testing.T, n int) *merge.Circuit {
	t.Helper()
	w := payment(t, n, n)
	m := merge.NewMergeCircuit(n)
	m.Asset, m.OwnerPkHash, m.UserNullifierSecret = 1, 42, 19
	m.UserSigningPkHash, m.UserNullifierPk = 42, hash(t, 19)
	m.ExternalDataHash, m.AllowDummyInputs, m.OutputTreeID = 29, 0, 11
	m.Output.RingDataHash = 0
	slots := make([]protocol.TreeSlot, len(m.TreeSlots))
	for i := range m.TreeSlots {
		id := 7 + i
		m.TreeSlots[i] = transaction.TreeSlot{ID: id, UtxoRoot: w.Certificate.StateRoot, NullifierRoot: w.Freshness.Root}
		slots[i] = protocol.TreeSlot{ID: big.NewInt(int64(id)), UtxoRoot: w.Certificate.StateRoot.(*big.Int), NullifierRoot: w.Freshness.Root.(*big.Int)}
	}
	owner := hash(t, 42, hash(t, 19))
	utxo := func(amount int, blinding *big.Int) protocol.Utxo {
		return protocol.Utxo{Domain: big.NewInt(protocol.UtxoDomain), Owner: owner, Asset: big.NewInt(1),
			Amount: big.NewInt(int64(amount)), Blinding: blinding, DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0)}
	}
	inputHashes, addresses := make([]*big.Int, n), make([]*big.Int, n)
	for i, note := range w.Certificate.Notes {
		f := w.Freshness.Witnesses[i]
		m.Inputs[i] = merge.Input{Domain: protocol.UtxoDomain, Amount: note.Amount, Blinding: note.Blinding, RingDataHash: 0,
			StatePathElements: note.Path, StatePathIndex: note.Index, TreeSlot: 0,
			NullifierLowValue: f.Low, NullifierNextValue: f.Next, NullifierLowPathIndex: f.Index, NullifierLowPathElements: f.Path}
		m.Nullifiers[i] = w.Certificate.Nullifiers[i]
		var err error
		inputHashes[i], err = protocol.UtxoHash(utxo(10, big.NewInt(int64(100+i))), big.NewInt(7))
		if err != nil {
			t.Fatal(err)
		}
		addresses[i] = big.NewInt(0)
	}
	blinding := hash(t, mergeshared.MergeOutputBlindingDomainV1, 19, m.Nullifiers[0])
	out, err := protocol.UtxoHash(utxo(n*10, blinding), big.NewInt(11))
	if err != nil {
		t.Fatal(err)
	}
	m.OutputHash = out
	privateBlinding, err := protocol.PrivateTxBlinding(m.Nullifiers[0].(*big.Int), big.NewInt(19))
	if err != nil {
		t.Fatal(err)
	}
	m.PrivateTxHash, err = protocol.PrivateTxHash(inputHashes, []*big.Int{out}, addresses, big.NewInt(29), privateBlinding)
	if err != nil {
		t.Fatal(err)
	}
	treesHash, err := protocol.TreeSlotsHashChain(slots)
	if err != nil {
		t.Fatal(err)
	}
	m.PublicInputHash = chain(t, []frontend.Variable{chain(t, m.Nullifiers), out, treesHash, 11, m.PrivateTxHash, 29, 0, 42})
	return m
}
