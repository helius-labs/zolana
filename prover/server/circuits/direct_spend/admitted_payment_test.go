package directspend_test

import (
	"fmt"
	"math/big"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	direct "zolana/prover/circuits/direct_spend"
	"zolana/prover/circuits/transcript"
	"zolana/prover/prover-test/spp/protocol"
)

func admittedPayment(t *testing.T, payment *direct.PaymentCircuit) *direct.AdmittedPaymentCircuit {
	t.Helper()
	w := &direct.AdmittedPaymentCircuit{Certificate: payment.Certificate, Balance: payment.Balance}
	bindAdmittedPayment(t, w)
	return w
}

func bindAdmittedPayment(t *testing.T, w *direct.AdmittedPaymentCircuit) {
	t.Helper()
	bindAdmittedPaymentDomain(t, w, direct.AdmittedPaymentDomain)
}

func bindAdmittedPaymentDomain(t *testing.T, w *direct.AdmittedPaymentCircuit, domain int) {
	t.Helper()
	fields := []frontend.Variable{domain}
	fields = append(fields, certificateFields(t, w.Certificate)...)
	fields = append(fields, balanceFields(t, w.Balance)...)
	w.PublicInputHash = chain(t, fields)
}

func TestAdmittedPayment(t *testing.T) {
	padded := payment(t, 4, 2)
	addSecondOutput(t, padded)
	for _, payment := range []*direct.PaymentCircuit{scatteredPayment(t, 4), padded} {
		if err := test.IsSolved(direct.NewAdmittedPayment(4, 2), admittedPayment(t, payment), ecc.BN254.ScalarField()); err != nil {
			t.Fatal(err)
		}
	}
}

// The inline shape: 100 notes, one output, admitted freshness.
func TestAdmittedInlinePayment(t *testing.T) {
	if testing.Short() {
		t.Skip("solves a 1.1M-constraint circuit")
	}
	for _, active := range []int{1, 100} {
		if err := test.IsSolved(direct.NewAdmittedPayment(100, 1), admittedPayment(t, payment(t, 100, active)), ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("active=%d: %v", active, err)
		}
	}
}

func TestAdmittedPaymentRejects(t *testing.T) {
	for name, mutate := range map[string]func(*direct.AdmittedPaymentCircuit){
		"inflation":      func(w *direct.AdmittedPaymentCircuit) { w.Balance.Outputs[0].Amount = 21 },
		"asset":          func(w *direct.AdmittedPaymentCircuit) { w.Balance.Asset = 2 },
		"owner":          func(w *direct.AdmittedPaymentCircuit) { w.Certificate.Owner = 99 },
		"secret":         func(w *direct.AdmittedPaymentCircuit) { w.Certificate.NullifierSecret = 99 },
		"tree":           func(w *direct.AdmittedPaymentCircuit) { w.Certificate.TreeID = 8 },
		"root":           func(w *direct.AdmittedPaymentCircuit) { w.Certificate.StateRoot = 1 },
		"path":           func(w *direct.AdmittedPaymentCircuit) { w.Certificate.Notes[1].Path[11] = 1 },
		"index":          func(w *direct.AdmittedPaymentCircuit) { w.Certificate.Notes[1].Index = 2 },
		"index overflow": func(w *direct.AdmittedPaymentCircuit) { w.Certificate.Notes[1].Index = uint64(1) << 32 },
		"nullifier":      func(w *direct.AdmittedPaymentCircuit) { w.Certificate.Nullifiers[0] = 1 },
		"count":          func(w *direct.AdmittedPaymentCircuit) { w.Certificate.Count = 3 },
		"empty":          func(w *direct.AdmittedPaymentCircuit) { w.Certificate.Count = 0 },
		"hidden amount":  func(w *direct.AdmittedPaymentCircuit) { w.Certificate.Notes[2].Amount = 1 },
		"amount overflow": func(w *direct.AdmittedPaymentCircuit) {
			w.Certificate.Notes[0].Amount = new(big.Int).Lsh(big.NewInt(1), 64)
		},
		"credit ID": func(w *direct.AdmittedPaymentCircuit) { w.Balance.Values[0].ID = 99 },
		"subtotal":  func(w *direct.AdmittedPaymentCircuit) { w.Balance.Values[0].Amount = 21 },
		"blinding":  func(w *direct.AdmittedPaymentCircuit) { w.Balance.Values[0].Randomness = 99 },
		"recipient": func(w *direct.AdmittedPaymentCircuit) { w.Balance.Outputs[0].OwnerKey = 99 },
		"output":    func(w *direct.AdmittedPaymentCircuit) { w.Balance.Outputs[0].Hash = 99 },
		"output overflow": func(w *direct.AdmittedPaymentCircuit) {
			w.Balance.Outputs[0].Amount = new(big.Int).Lsh(big.NewInt(1), 64)
		},
		"conservation": func(w *direct.AdmittedPaymentCircuit) {
			output := &w.Balance.Outputs[0]
			output.Amount = 21
			outputHash, err := protocol.UtxoHash(protocol.Utxo{
				Domain: big.NewInt(protocol.UtxoDomain), Owner: hash(t, output.OwnerKey, output.NullifierPK),
				Asset: big.NewInt(1), Amount: big.NewInt(21), Blinding: big.NewInt(53),
				DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0),
			}, big.NewInt(11))
			if err != nil {
				t.Fatal(err)
			}
			output.Hash = outputHash
		},
		"padding gap": func(w *direct.AdmittedPaymentCircuit) {
			w.Certificate.Nullifiers[0], w.Certificate.Nullifiers[2] = w.Certificate.Nullifiers[2], w.Certificate.Nullifiers[0]
			w.Certificate.Notes[0], w.Certificate.Notes[2] = w.Certificate.Notes[2], w.Certificate.Notes[0]
		},
	} {
		t.Run(name, func(t *testing.T) {
			payment := payment(t, 4, 2)
			addSecondOutput(t, payment)
			w := admittedPayment(t, payment)
			mutate(w)
			bindAdmittedPayment(t, w)
			if err := test.IsSolved(direct.NewAdmittedPayment(4, 2), w, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("accepted invalid admitted payment")
			}
		})
	}
	for _, field := range []string{"domain", "intent", "hash"} {
		t.Run(field, func(t *testing.T) {
			payment := scatteredPayment(t, 4)
			w := admittedPayment(t, payment)
			switch field {
			case "domain":
				w.PublicInputHash = payment.PublicInputHash
			case "intent":
				w.Balance.Intent = 99
			case "hash":
				w.PublicInputHash = 1
			}
			if err := test.IsSolved(direct.NewAdmittedPayment(4, 2), w, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("accepted invalid public binding")
			}
		})
	}
}

func prefixAdmittedPayment(t *testing.T, height int, name string) *direct.PrefixAdmittedPayment {
	t.Helper()
	payment := scatteredPaymentAtHeight(t, 4, height)
	w := direct.NewPrefixAdmittedPayment(4, height, name)
	w.AdmittedPaymentCircuit = *admittedPayment(t, payment)
	note := w.Certificate.Notes[0]
	root := certificateLeaf(t, w.Certificate, note)
	for level, sibling := range note.Path[:height] {
		if note.Index.(uint64)>>level&1 == 0 {
			root = hash(t, root, sibling)
		} else {
			root = hash(t, sibling, root)
		}
	}
	w.PrefixRoot = root
	for i := range w.Certificate.Notes {
		w.Certificate.Notes[i].Path = w.Certificate.Notes[i].Path[:height]
	}
	return w
}

func certificateLeaf(t *testing.T, certificate direct.Certificate, note direct.Note) *big.Int {
	t.Helper()
	values := integers(t, []frontend.Variable{note.Amount, note.Blinding, certificate.TreeID, certificate.Asset})
	leaf, err := protocol.UtxoHash(protocol.Utxo{
		Domain: big.NewInt(protocol.UtxoDomain), Owner: hash(t, certificate.Owner, hash(t, certificate.NullifierSecret)),
		Asset: values[3], Amount: values[0], Blinding: values[1], DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0),
	}, values[2])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func dagAdmittedPayment(t *testing.T, payment *direct.PaymentCircuit, height int) *direct.DAGAdmittedPayment {
	t.Helper()
	w := direct.NewDAGAdmittedPayment(len(payment.Certificate.Notes), height)
	w.AdmittedPaymentCircuit = *admittedPayment(t, payment)
	pairs := make([]map[uint64][2]*big.Int, 32)
	rows := make([]map[uint64]int, 32)
	for level := range pairs {
		pairs[level] = make(map[uint64][2]*big.Int)
		rows[level] = make(map[uint64]int)
	}
	active := int(integers(t, []frontend.Variable{w.Certificate.Count})[0].Int64())
	for _, note := range w.Certificate.Notes[:active] {
		index := integers(t, []frontend.Variable{note.Index})[0].Uint64()
		current := certificateLeaf(t, w.Certificate, note)
		for level, sibling := range note.Path {
			sib := integers(t, []frontend.Variable{sibling})[0]
			pair := [2]*big.Int{current, sib}
			if index>>level&1 != 0 {
				pair[0], pair[1] = pair[1], pair[0]
			}
			pairs[level][index>>(level+1)] = pair
			current = hash(t, pair[0], pair[1])
		}
	}
	keys := make([][]uint64, 32)
	for level, pairs := range pairs {
		for index := range pairs {
			keys[level] = append(keys[level], index)
		}
		sort.Slice(keys[level], func(i, j int) bool { return keys[level][i] < keys[level][j] })
		for row, index := range keys[level] {
			rows[level][index] = row
		}
	}
	for level := range w.Levels {
		if len(keys[level]) > len(w.Levels[level]) {
			t.Fatal("fixture exceeds DAG shape")
		}
		for row := range w.Levels[level] {
			index := keys[level][row%len(keys[level])]
			pair := pairs[level][index]
			parent := 0
			if level < 31 {
				parent = rows[level+1][index>>1]*2 + int(index&1)
			}
			w.Levels[level][row] = direct.DAGPair{Left: pair[0], Right: pair[1], Parent: parent}
		}
	}
	for i, note := range w.Certificate.Notes {
		w.LeafRef[i] = 0
		if i < active {
			index := integers(t, []frontend.Variable{note.Index})[0].Uint64()
			w.LeafRef[i] = rows[0][index>>1]*2 + int(index&1)
		}
		w.Certificate.Notes[i].Path = nil
	}
	bindAdmittedPaymentDomain(t, &w.AdmittedPaymentCircuit, direct.AdmittedDAGPaymentDomain)
	return w
}

func TestAdmittedDAGPayment(t *testing.T) {
	for _, height := range []int{10, 16} {
		padded := payment(t, 4, 2)
		addSecondOutput(t, padded)
		for _, payment := range []*direct.PaymentCircuit{scatteredPaymentAtHeight(t, 4, height), padded} {
			if err := test.IsSolved(direct.NewDAGAdmittedPayment(4, height), dagAdmittedPayment(t, payment, height), ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
		}
	}
	w := dagAdmittedPayment(t, scatteredPaymentAtHeight(t, 4, 10), 10)
	bindAdmittedPayment(t, &w.AdmittedPaymentCircuit)
	if err := test.IsSolved(direct.NewDAGAdmittedPayment(4, 10), w, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("accepted the ordinary admitted payment domain")
	}
	for name, mutate := range map[string]func(*direct.DAGAdmittedPayment){
		"root":   func(w *direct.DAGAdmittedPayment) { w.Certificate.StateRoot = 1 },
		"node":   func(w *direct.DAGAdmittedPayment) { w.Levels[0][1].Left = 1 },
		"parent": func(w *direct.DAGAdmittedPayment) { w.Levels[0][1].Parent = 999 },
		"in-range parent": func(w *direct.DAGAdmittedPayment) {
			parent := integers(t, []frontend.Variable{w.Levels[0][1].Parent})[0].Int64()
			w.Levels[0][1].Parent = (parent + 1) % int64(2*len(w.Levels[1]))
		},
		"leaf reference": func(w *direct.DAGAdmittedPayment) { w.LeafRef[0] = 999 },
		"in-range leaf reference": func(w *direct.DAGAdmittedPayment) {
			reference := integers(t, []frontend.Variable{w.LeafRef[0]})[0].Int64()
			w.LeafRef[0] = (reference + 1) % int64(2*len(w.Levels[0]))
		},
		"index":          func(w *direct.DAGAdmittedPayment) { w.Certificate.Notes[0].Index = 0 },
		"index overflow": func(w *direct.DAGAdmittedPayment) { w.Certificate.Notes[0].Index = uint64(1) << 10 },
	} {
		t.Run(name, func(t *testing.T) {
			w := dagAdmittedPayment(t, scatteredPaymentAtHeight(t, 4, 10), 10)
			mutate(w)
			bindAdmittedPaymentDomain(t, &w.AdmittedPaymentCircuit, direct.AdmittedDAGPaymentDomain)
			if err := test.IsSolved(direct.NewDAGAdmittedPayment(4, 10), w, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("accepted invalid DAG payment")
			}
		})
	}
}

func TestAdmittedDAGBindsDuplicateLeafPosition(t *testing.T) {
	payment := payment(t, 4, 1)
	addSecondOutput(t, payment)
	leaf := certificateLeaf(t, payment.Certificate, payment.Certificate.Notes[0])
	root, paths, err := protocol.BuildSparseStateTree(map[uint64]*big.Int{0: leaf, 1: leaf})
	if err != nil {
		t.Fatal(err)
	}
	payment.Certificate.StateRoot = root
	payment.Certificate.Notes[0].Index = uint64(0)
	payment.Certificate.Notes[0].Path = variables(paths[0].PathElements)
	w := dagAdmittedPayment(t, payment, 10)
	c := direct.NewDAGAdmittedPayment(4, 10)
	if err := test.IsSolved(c, w, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	w.Certificate.Notes[0].Index = 1
	if err := test.IsSolved(c, w, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("accepted the same leaf hash paired with the wrong private position")
	}
	w.LeafRef[0] = 1
	if err := test.IsSolved(c, w, ecc.BN254.ScalarField()); err != nil {
		t.Fatal("rejected the matching hash-position pair", err)
	}
}

func TestAdmittedOccupiedPrefix(t *testing.T) {
	payment := scatteredPaymentAtHeight(t, 4, 10)
	leaves := map[uint64]*big.Int{1 << 10: hash(t, 991, 722)}
	for _, note := range payment.Certificate.Notes {
		leaves[note.Index.(uint64)] = certificateLeaf(t, payment.Certificate, note)
	}
	root, witnesses, err := protocol.BuildSparseStateTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	payment.Certificate.StateRoot = root
	for i, note := range payment.Certificate.Notes {
		payment.Certificate.Notes[i].Path = variables(witnesses[note.Index.(uint64)].PathElements)
	}
	dag := dagAdmittedPayment(t, payment, 10)
	prefix := prefixAdmittedPayment(t, 10, "POSEIDON2")
	prefix.Certificate.StateRoot = root
	bindAdmittedPayment(t, &prefix.AdmittedPaymentCircuit)
	for _, pair := range []struct{ circuit, witness frontend.Circuit }{
		{direct.NewDAGAdmittedPayment(4, 10), dag},
		{direct.NewPrefixAdmittedPayment(4, 10, "POSEIDON2"), prefix},
	} {
		if err := test.IsSolved(pair.circuit, pair.witness, ecc.BN254.ScalarField()); err == nil {
			t.Fatalf("%T accepted a populated subtree outside the occupied prefix", pair.circuit)
		}
	}
}

func TestAdmittedPrefixPayment(t *testing.T) {
	transcript.Register()
	for _, height := range []int{10, 16, 20, 32} {
		for _, name := range []string{"POSEIDON2", transcript.NameForWidth(12)} {
			w := prefixAdmittedPayment(t, height, name)
			if err := test.IsSolved(direct.NewPrefixAdmittedPayment(4, height, name), w, ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, mutate := range map[string]func(*direct.PrefixAdmittedPayment){
		"root":   func(w *direct.PrefixAdmittedPayment) { w.Certificate.StateRoot = 1 },
		"prefix": func(w *direct.PrefixAdmittedPayment) { w.PrefixRoot = 1 },
		"path":   func(w *direct.PrefixAdmittedPayment) { w.Certificate.Notes[2].Path[3] = 1 },
		"index":  func(w *direct.PrefixAdmittedPayment) { w.Certificate.Notes[0].Index = uint64(1) << 10 },
	} {
		t.Run(name, func(t *testing.T) {
			w := prefixAdmittedPayment(t, 10, transcript.NameForWidth(12))
			mutate(w)
			bindAdmittedPayment(t, &w.AdmittedPaymentCircuit)
			if err := test.IsSolved(direct.NewPrefixAdmittedPayment(4, 10, transcript.NameForWidth(12)), w, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("accepted invalid prefix payment")
			}
		})
	}
}

func TestAdmittedPaymentConstraints(t *testing.T) {
	if os.Getenv("ADMITTED_PAYMENT_COUNTS") == "" {
		t.Skip("set ADMITTED_PAYMENT_COUNTS=1")
	}
	for _, shape := range [][2]int{{100, 1}, {144, 2}, {512, 2}} {
		inputs, outputs := shape[0], shape[1]
		t.Run(fmt.Sprintf("%dx%d", inputs, outputs), func(t *testing.T) {
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, direct.NewAdmittedPayment(inputs, outputs), frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			commitments := cs.GetCommitments().(constraint.Groth16Commitments)
			if len(commitments) != 1 || len(commitments[0].PublicAndCommitmentCommitted) != 0 || cs.GetNbPublicVariables() != 2 {
				t.Fatal("admitted payment does not match the single private BSB22 commitment verifier")
			}
			t.Logf("ADMITTED_PAYMENT inputs=%d outputs=%d constraints=%d public_variables=%d private_committed=%d digest=%s", inputs, outputs, cs.GetNbConstraints(), cs.GetNbPublicVariables(), len(commitments[0].PrivateCommitted), constraintDigest(t, cs))
			for _, blueprint := range cs.(*csbn254.R1CS).Blueprints {
				if reflect.TypeOf(blueprint).Elem().Name() == "BlueprintProve" {
					elements := blueprint.NbOutputs(constraint.Instruction{})
					t.Logf("ADMITTED_GKR_TRANSCRIPT inputs=%d proof_elements=%d proof_bytes=%d", inputs, elements, elements*32)
				}
			}
		})
	}
}
