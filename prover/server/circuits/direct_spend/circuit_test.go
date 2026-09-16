package directspend_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	direct "zolana/prover/circuits/direct_spend"
	"zolana/prover/prover-test/poseidon"
	"zolana/prover/prover-test/spp/protocol"
)

func TestPayment(t *testing.T) {
	for _, active := range []int{1, 2, 4} {
		t.Run(fmt.Sprint(active), func(t *testing.T) {
			w := payment(t, 4, active)
			if err := test.IsSolved(direct.NewPayment(4, 1), w, ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIndependentProofs(t *testing.T) {
	w := payment(t, 4, 2)
	assignments := []struct{ circuit, witness frontend.Circuit }{
		{direct.NewCertificate(4), &direct.CertificateCircuit{Certificate: w.Certificate, PublicInputHash: chain(t, certificateFields(t, w.Certificate))}},
		{direct.NewFreshness(4), &direct.FreshnessCircuit{Freshness: w.Freshness, PublicInputHash: chain(t, freshnessFields(t, w.Freshness))}},
		{direct.NewBalance(1, 1), &direct.BalanceCircuit{Balance: w.Balance, PublicInputHash: chain(t, balanceFields(t, w.Balance))}},
	}
	for _, pair := range assignments {
		if err := test.IsSolved(pair.circuit, pair.witness, ecc.BN254.ScalarField()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPaymentRejects(t *testing.T) {
	cases := map[string]func(*direct.PaymentCircuit){
		"inflation":       func(w *direct.PaymentCircuit) { w.Balance.Outputs[0].Amount = 21 },
		"wrong asset":     func(w *direct.PaymentCircuit) { w.Balance.Asset = 2 },
		"wrong owner":     func(w *direct.PaymentCircuit) { w.Certificate.Owner = 99 },
		"wrong tree":      func(w *direct.PaymentCircuit) { w.Certificate.TreeID = 8 },
		"wrong root":      func(w *direct.PaymentCircuit) { w.Certificate.StateRoot = 1 },
		"wrong nullifier": func(w *direct.PaymentCircuit) { w.Certificate.Nullifiers[0] = 1 },
		"wrong count":     func(w *direct.PaymentCircuit) { w.Certificate.Count = 3 },
		"hidden amount":   func(w *direct.PaymentCircuit) { w.Certificate.Notes[2].Amount = 1 },
		"amount overflow": func(w *direct.PaymentCircuit) { w.Certificate.Notes[0].Amount = new(big.Int).Lsh(big.NewInt(1), 64) },
		"wrong credit":    func(w *direct.PaymentCircuit) { w.Balance.Values[0].ID = 99 },
		"wrong subtotal":  func(w *direct.PaymentCircuit) { w.Balance.Values[0].Amount = 21 },
		"wrong blinding":  func(w *direct.PaymentCircuit) { w.Balance.Values[0].Randomness = 99 },
		"wrong recipient": func(w *direct.PaymentCircuit) { w.Balance.Outputs[0].OwnerKey = 99 },
		"wrong output":    func(w *direct.PaymentCircuit) { w.Balance.Outputs[0].Hash = 99 },
		"wrong nf root":   func(w *direct.PaymentCircuit) { w.Freshness.Root = 1 },
		"spent nullifier": func(w *direct.PaymentCircuit) { w.Freshness.Witnesses[0].Low = w.Freshness.Nullifiers[0] },
		"nf substitution": func(w *direct.PaymentCircuit) { w.Freshness.Nullifiers[0] = 1 },
		"padding gap": func(w *direct.PaymentCircuit) {
			w.Certificate.Nullifiers[0], w.Certificate.Nullifiers[2] = w.Certificate.Nullifiers[2], w.Certificate.Nullifiers[0]
			w.Certificate.Notes[0], w.Certificate.Notes[2] = w.Certificate.Notes[2], w.Certificate.Notes[0]
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := payment(t, 4, 2)
			mutate(w)
			bindPayment(t, w)
			if err := test.IsSolved(direct.NewPayment(4, 1), w, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("invalid payment satisfied the circuit")
			}
		})
	}
}

func TestCircuitConstraints(t *testing.T) {
	for _, n := range []int{36, 128, 512} {
		for _, circuit := range []frontend.Circuit{direct.NewCertificate(n), direct.NewFreshness(n), direct.NewPayment(n, 1)} {
			t.Run(fmt.Sprintf("%T/%d", circuit, n), func(t *testing.T) {
				if testing.Short() && n > 36 {
					t.Skip("wide circuit compilation")
				}
				cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("%d constraints", cs.GetNbConstraints())
			})
		}
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, direct.NewBalance(16, 2), frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("16-certificate balance: %d constraints", cs.GetNbConstraints())
}

func payment(t *testing.T, slots, active int) *direct.PaymentCircuit {
	t.Helper()
	w := direct.NewPayment(slots, 1)
	c := &w.Certificate
	c.ID, c.TreeID, c.Owner, c.Count = 17, 7, 42, active
	c.Asset, c.NullifierSecret, c.ValueRandomness = 1, 19, 23
	owner := hash(t, 42, hash(t, 19))
	leaves := make(map[uint64]*big.Int)
	nfs, err := protocol.NewNullifierTree()
	if err != nil {
		t.Fatal(err)
	}
	w.Freshness.TreeID, w.Freshness.Root, w.Freshness.Count = 7, nfs.Root(), active
	for i := 0; i < slots; i++ {
		c.Notes[i] = direct.Note{Amount: 0, Blinding: 0, Index: 0, Path: zeros(32)}
		c.Nullifiers[i], w.Freshness.Nullifiers[i] = 0, 0
		w.Freshness.Witnesses[i] = direct.NonInclusion{Low: 0, Next: 0, Index: 0, Path: zeros(40)}
		if i >= active {
			continue
		}
		utxo := protocol.Utxo{
			Domain: big.NewInt(protocol.UtxoDomain), Owner: owner, Asset: big.NewInt(1),
			Amount: big.NewInt(10), Blinding: big.NewInt(int64(100 + i)),
			DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0),
		}
		leaf, err := protocol.UtxoHash(utxo, big.NewInt(7))
		if err != nil {
			t.Fatal(err)
		}
		leaves[uint64(i)] = leaf
		nullifier, err := protocol.Nullifier(leaf, utxo.Blinding, big.NewInt(19))
		if err != nil {
			t.Fatal(err)
		}
		witness, err := nfs.NonInclusionWitness(nullifier)
		if err != nil {
			t.Fatal(err)
		}
		c.Notes[i].Amount, c.Notes[i].Blinding, c.Notes[i].Index = 10, utxo.Blinding, i
		c.Nullifiers[i], w.Freshness.Nullifiers[i] = nullifier, nullifier
		w.Freshness.Witnesses[i] = direct.NonInclusion{
			Low: witness.LowValue, Next: witness.NextValue, Index: witness.LowIndex, Path: variables(witness.PathElements),
		}
	}
	root, witnesses, err := protocol.BuildSparseStateTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	c.StateRoot = root
	for i := 0; i < active; i++ {
		c.Notes[i].Path = variables(witnesses[uint64(i)].PathElements)
	}
	c.ValueCommitment = hash(t, direct.ValueDomain, 17, 1, active*10, 23)
	w.Balance.Intent, w.Balance.OutputTreeID, w.Balance.Asset = 29, 11, 1
	w.Balance.Values[0] = direct.Value{ID: 17, Commitment: c.ValueCommitment, Amount: active * 10, Randomness: 23}
	outOwner := hash(t, 43, 47)
	out, err := protocol.UtxoHash(protocol.Utxo{
		Domain: big.NewInt(protocol.UtxoDomain), Owner: outOwner, Asset: big.NewInt(1), Amount: big.NewInt(int64(active * 10)),
		Blinding: big.NewInt(53), DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0),
	}, big.NewInt(11))
	if err != nil {
		t.Fatal(err)
	}
	w.Balance.Outputs[0] = direct.Output{OwnerKey: 43, NullifierPK: 47, Amount: active * 10, Blinding: 53, Hash: out}
	bindPayment(t, w)
	return w
}

func bindPayment(t *testing.T, w *direct.PaymentCircuit) {
	fields := []frontend.Variable{direct.PaymentDomain}
	fields = append(fields, certificateFields(t, w.Certificate)...)
	fields = append(fields, freshnessFields(t, w.Freshness)...)
	fields = append(fields, balanceFields(t, w.Balance)...)
	w.PublicInputHash = chain(t, fields)
}

func certificateFields(t *testing.T, c direct.Certificate) []frontend.Variable {
	return []frontend.Variable{direct.CertificateDomain, c.ID, c.TreeID, c.StateRoot, c.Owner, c.Count, chain(t, c.Nullifiers), c.ValueCommitment}
}

func freshnessFields(t *testing.T, f direct.Freshness) []frontend.Variable {
	return []frontend.Variable{direct.FreshnessDomain, f.TreeID, f.Root, f.Count, chain(t, f.Nullifiers)}
}

func balanceFields(t *testing.T, b direct.Balance) []frontend.Variable {
	values, outputs := []frontend.Variable{}, []frontend.Variable{}
	for _, v := range b.Values {
		values = append(values, v.ID, v.Commitment)
	}
	for _, o := range b.Outputs {
		outputs = append(outputs, o.Hash, o.OwnerKey)
	}
	return []frontend.Variable{direct.BalanceDomain, b.Intent, b.OutputTreeID, chain(t, values), chain(t, outputs)}
}

func hash(t *testing.T, values ...frontend.Variable) *big.Int {
	t.Helper()
	h, err := poseidon.Hash(integers(t, values))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func chain(t *testing.T, values []frontend.Variable) *big.Int {
	t.Helper()
	h, err := protocol.HashChain4(integers(t, values))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func integers(t *testing.T, values []frontend.Variable) []*big.Int {
	t.Helper()
	result := make([]*big.Int, len(values))
	for i, v := range values {
		var ok bool
		result[i], ok = new(big.Int).SetString(fmt.Sprint(v), 10)
		if !ok {
			t.Fatalf("invalid field: %v", v)
		}
	}
	return result
}

func variables(values []*big.Int) []frontend.Variable {
	result := make([]frontend.Variable, len(values))
	for i, value := range values {
		result[i] = value
	}
	return result
}

func zeros(n int) []frontend.Variable {
	result := make([]frontend.Variable, n)
	for i := range result {
		result[i] = 0
	}
	return result
}

func TestPaddedBalance(t *testing.T) {
	w := payment(t, 4, 2)
	balance := direct.NewBalance(16, 1)
	balance.Balance.Intent, balance.OutputTreeID, balance.Asset = w.Balance.Intent, w.Balance.OutputTreeID, w.Balance.Asset
	balance.Values[0] = w.Balance.Values[0]
	balance.Outputs[0] = w.Balance.Outputs[0]
	for i := 1; i < len(balance.Values); i++ {
		balance.Values[i] = direct.Value{ID: 0, Commitment: 0, Amount: 0, Randomness: 0}
	}
	bind := func() { balance.PublicInputHash = chain(t, balanceFields(t, balance.Balance)) }
	bind()
	if err := test.IsSolved(direct.NewBalance(16, 1), balance, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	balance.Values[1].Amount = 1
	bind()
	if err := test.IsSolved(direct.NewBalance(16, 1), balance, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("padding minted value")
	}
}
