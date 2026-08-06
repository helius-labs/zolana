//go:build aggregate_keys

package aggregate

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
	transaction "zolana/prover/prover-test/spp/prover/transaction"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark/backend/groth16"
)

// The uncommitted rails compile to one outer circuit per batch size, so the
// ring numbers carry over to the confidential rail and to the mixed
// uncommitted shapes.
func TestAggregateProveCostRingLegs(t *testing.T) {
	if testing.Short() {
		t.Skip("proves multi-million constraint circuits")
	}
	inner := loadInnerSystem(t, ringSlot())
	if inner == nil {
		return
	}

	for _, batch := range []uint32{2, 3} {
		p := Uniform(common.TransferRingCircuitType, 2, 3, batch)
		path := filepath.Join(keysDir(), p.KeyName())
		if _, err := os.Stat(path); err != nil {
			t.Logf("skipping %s, missing key", p.KeyName())
			continue
		}
		system, err := common.ReadSystemFromFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		ps, ok := system.(*common.AggregateProofSystem)
		if !ok {
			t.Fatalf("%s read as %T", path, system)
		}

		legStart := time.Now()
		legs, hashes, err := buildRingLegs(inner, int(batch))
		if err != nil {
			t.Fatal(err)
		}
		legTime := time.Since(legStart)

		var proof *common.Proof
		var cold, warm time.Duration
		for run, target := range []*time.Duration{&cold, &warm} {
			start := time.Now()
			if proof, err = ProveAggregate(ps, legs); err != nil {
				t.Fatalf("outer prove run %d: %v", run, err)
			}
			*target = time.Since(start)
		}

		chain, err := AggregateInputHash(hashes)
		if err != nil {
			t.Fatal(err)
		}
		public, err := publicWitness(chain)
		if err != nil {
			t.Fatal(err)
		}
		if err := groth16.Verify(proof.Proof, ps.VerifyingKey, public); err != nil {
			t.Fatalf("outer proof rejected natively: %v", err)
		}
		t.Logf("%s: legs=%s cold=%s warm=%s",
			p.KeyName(), legTime.Round(time.Millisecond), cold.Round(time.Millisecond), warm.Round(time.Millisecond))
	}
}

func buildRingLegs(inner *common.TransferProofSystem, batch int) ([]Leg, []*big.Int, error) {
	shape := protocol.Shape{NInputs: int(inner.NInputs), NOutputs: int(inner.NOutputs)}
	ps := &transaction.ProofSystem{
		Shape:            shape,
		ConstraintSystem: inner.ConstraintSystem,
		ProvingKey:       inner.ProvingKey,
		VerifyingKey:     inner.VerifyingKey,
	}

	var payerPubkey [32]byte
	for i := range payerPubkey {
		payerPubkey[i] = byte(i + 1)
	}
	request := transaction.ProofBundleRequest{PayerPubkey: parse.BytesHex(payerPubkey[:])}
	for i := 0; i < batch; i++ {
		tx, err := ringTransferRequest(shape, payerPubkey, int64(i))
		if err != nil {
			return nil, nil, fmt.Errorf("leg %d request: %w", i, err)
		}
		request.Transactions = append(request.Transactions, tx)
	}
	bundle, err := transaction.BuildProofBundle(ps, request)
	if err != nil {
		return nil, nil, fmt.Errorf("prove inner batch: %w", err)
	}

	legs := make([]Leg, batch)
	hashes := make([]*big.Int, batch)
	for i, tx := range bundle.Transactions {
		hash, err := parse.Field("0x" + tx.PublicInputHash)
		if err != nil {
			return nil, nil, fmt.Errorf("leg %d hash: %w", i, err)
		}
		public, err := publicWitness(hash)
		if err != nil {
			return nil, nil, fmt.Errorf("leg %d: %w", i, err)
		}
		legs[i] = Leg{Proof: tx.Proof.Proof, PublicWitness: public}
		hashes[i] = hash
	}
	return legs, hashes, nil
}

func ringTransferRequest(shape protocol.Shape, payerPubkey [32]byte, seed int64) (transaction.ProofTransactionRequest, error) {
	ownerKeyHash, err := protocol.SolanaPkField(payerPubkey)
	if err != nil {
		return transaction.ProofTransactionRequest{}, err
	}
	nullifierSecret := big.NewInt(12345 + seed)
	nullifierPk, err := protocol.NullifierPk(nullifierSecret)
	if err != nil {
		return transaction.ProofTransactionRequest{}, err
	}
	owner, err := protocol.OwnerHash(ownerKeyHash, nullifierPk)
	if err != nil {
		return transaction.ProofTransactionRequest{}, err
	}

	tx := transaction.ProofTransactionRequest{
		Name:                     fmt.Sprintf("prove-cost-seed-%d", seed),
		InstructionDiscriminator: 1,
		ExpiryUnixTs:             123,
		SenderViewTag:            fieldInput(big.NewInt(9)),
		EncryptedUtxos:           "00",
		DataHash:                 fieldInput(big.NewInt(0)),
		RingDataHash:             fieldInput(big.NewInt(0)),
	}

	inputAmount := big.NewInt(int64(shape.NOutputs * 10))
	outputAmount := big.NewInt(int64(shape.NInputs * 10))
	for i := 0; i < shape.NInputs; i++ {
		utxo := protocol.Utxo{
			Domain:        big.NewInt(protocol.UtxoDomain),
			Owner:         owner,
			Asset:         protocol.SolAsset(),
			Amount:        new(big.Int).Set(inputAmount),
			Blinding:      big.NewInt(1000 + seed*100 + int64(i)),
			DataHash:      big.NewInt(0),
			RingDataHash:  big.NewInt(0),
			RingProgramID: big.NewInt(0),
		}
		hash, err := protocol.UtxoHash(utxo)
		if err != nil {
			return transaction.ProofTransactionRequest{}, err
		}
		tx.StateEntries = append(tx.StateEntries, transaction.ProofStateEntry{
			Index: uint64(i),
			Hash:  fieldInput(hash),
		})
		tx.Inputs = append(tx.Inputs, transaction.ProofInputRequest{
			Utxo: transaction.ProofUtxoRequest{
				Domain:            fieldInput(utxo.Domain),
				Asset:             fieldInput(utxo.Asset),
				Amount:            fieldInput(utxo.Amount),
				Blinding:          fieldInput(utxo.Blinding),
				DataHash:          fieldInput(utxo.DataHash),
				RingDataHash:      fieldInput(utxo.RingDataHash),
				RingProgramID:     fieldInput(utxo.RingProgramID),
				OwnerSolanaPubkey: parse.BytesHex(payerPubkey[:]),
			},
			LeafIndex:       uint64(i),
			NullifierSecret: fieldInput(nullifierSecret),
		})
	}
	for i := 0; i < shape.NOutputs; i++ {
		tx.Outputs = append(tx.Outputs, transaction.ProofUtxoRequest{
			Domain:               fieldInput(big.NewInt(protocol.UtxoDomain)),
			Owner:                fieldInput(owner),
			OwnerSolanaPubkey:    parse.BytesHex(payerPubkey[:]),
			OwnerNullifierSecret: fieldInput(nullifierSecret),
			Asset:                fieldInput(protocol.SolAsset()),
			Amount:               fieldInput(outputAmount),
			Blinding:             fieldInput(big.NewInt(2000 + seed*100 + int64(i))),
			DataHash:             fieldInput(big.NewInt(0)),
			RingDataHash:         fieldInput(big.NewInt(0)),
			RingProgramID:        fieldInput(big.NewInt(0)),
		})
	}
	return tx, nil
}

func fieldInput(value *big.Int) string {
	return "0x" + parse.FieldHex(value)
}
