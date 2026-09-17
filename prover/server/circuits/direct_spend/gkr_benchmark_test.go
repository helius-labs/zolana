package directspend_test

import (
	"fmt"
	"math/big"
	"math/rand/v2"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	direct "zolana/prover/circuits/direct_spend"
	"zolana/prover/circuits/transcript"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover/common"
)

func scatteredPayment(t *testing.T, n int) *direct.PaymentCircuit {
	return scatteredPaymentAtHeight(t, n, 32)
}

func scatteredPaymentAtHeight(t *testing.T, n, height int) *direct.PaymentCircuit {
	t.Helper()
	w := payment(t, n, n)
	addSecondOutput(t, w)
	rng := rand.New(rand.NewPCG(417, 999))
	leaves := make(map[uint64]*big.Int, n)
	owner := hash(t, w.Certificate.Owner, hash(t, w.Certificate.NullifierSecret))
	for i, note := range w.Certificate.Notes {
		index := uint64(rng.Uint32()) & ((uint64(1) << height) - 1)
		for leaves[index] != nil {
			index = uint64(rng.Uint32()) & ((uint64(1) << height) - 1)
		}
		values := integers(t, []frontend.Variable{note.Amount, note.Blinding, w.Certificate.TreeID, w.Certificate.Asset})
		leaf, err := protocol.UtxoHash(protocol.Utxo{
			Domain: big.NewInt(protocol.UtxoDomain), Owner: owner, Asset: values[3], Amount: values[0],
			Blinding: values[1], DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0),
		}, values[2])
		if err != nil {
			t.Fatal(err)
		}
		leaves[index] = leaf
		w.Certificate.Notes[i].Index = index
	}
	root, paths, err := protocol.BuildSparseStateTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	w.Certificate.StateRoot = root
	for i, note := range w.Certificate.Notes {
		w.Certificate.Notes[i].Path = variables(paths[note.Index.(uint64)].PathElements)
	}
	nfs, err := protocol.NewNullifierTree()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 64 {
		if err := nfs.Insert(hash(t, 991, i)); err != nil {
			t.Fatal(err)
		}
	}
	w.Freshness.Root = nfs.Root()
	for i, nf := range w.Freshness.Nullifiers {
		witness, err := nfs.NonInclusionWitness(integers(t, []frontend.Variable{nf})[0])
		if err != nil {
			t.Fatal(err)
		}
		w.Freshness.Witnesses[i] = direct.NonInclusion{
			Low: witness.LowValue, Next: witness.NextValue, Index: witness.LowIndex, Path: variables(witness.PathElements),
		}
	}
	bindPayment(t, w)
	return w
}

func TestScatteredGKRPayment(t *testing.T) {
	c := direct.NewPayment(4, 2)
	c.GKR = true
	padded := payment(t, 4, 2)
	addSecondOutput(t, padded)
	for _, w := range []*direct.PaymentCircuit{scatteredPayment(t, 4), padded} {
		if err := test.IsSolved(c, w, ecc.BN254.ScalarField()); err != nil {
			t.Fatal(err)
		}
	}
	for name, mutate := range map[string]func(*direct.PaymentCircuit){
		"inflation": func(w *direct.PaymentCircuit) { w.Balance.Outputs[0].Amount = 41 },
		"path":      func(w *direct.PaymentCircuit) { w.Certificate.Notes[1].Path[11] = 1 },
		"nullifier": func(w *direct.PaymentCircuit) { w.Freshness.Witnesses[1].Low = w.Freshness.Nullifiers[1] },
	} {
		t.Run(name, func(t *testing.T) {
			w := scatteredPayment(t, 4)
			mutate(w)
			bindPayment(t, w)
			if err := test.IsSolved(c, w, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("accepted invalid payment")
			}
		})
	}
}

// The inline shape: 100 notes, one output, non-inclusion at the checkpoint
// root, GKR-compressed.
func TestInlineGKRPayment(t *testing.T) {
	if testing.Short() {
		t.Skip("solves a 1.4M-constraint circuit")
	}
	c := direct.NewPayment(100, 1)
	c.GKR = true
	for _, active := range []int{1, 100} {
		if err := test.IsSolved(c, payment(t, 100, active), ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("active=%d: %v", active, err)
		}
	}
}

func TestScatteredGKRPaymentProving(t *testing.T) {
	n, err := strconv.Atoi(os.Getenv("GKR_PAYMENT_INPUTS"))
	if err != nil || n < 1 || n > 512 {
		t.Skip("set GKR_PAYMENT_INPUTS to 1..512")
	}
	t.Logf("go=%s arch=%s cpus=%d gomaxprocs=%d memory_limit=%s", runtime.Version(), runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0), os.Getenv("GOMEMLIMIT"))
	start := time.Now()
	w := scatteredPayment(t, n)
	t.Logf("PAYMENT_WITNESS inputs=%d build_ms=%d", n, time.Since(start).Milliseconds())
	for _, accelerated := range []bool{false, true} {
		t.Run(fmt.Sprintf("gkr=%t", accelerated), func(t *testing.T) {
			c := direct.NewPayment(n, 2)
			c.GKR = accelerated
			if width, _ := strconv.Atoi(os.Getenv("GKR_TRANSCRIPT_WIDTH")); width != 0 {
				transcript.Register()
				c.Transcript = transcript.NameForWidth(width)
			}
			start := time.Now()
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("GKR_PAYMENT_COMPILE inputs=%d gkr=%t constraints=%d compile_ms=%d", n, accelerated, cs.GetNbConstraints(), time.Since(start).Milliseconds())
			if accelerated {
				commitments := cs.GetCommitments().(constraint.Groth16Commitments)
				if len(commitments) != 1 || len(commitments[0].PublicAndCommitmentCommitted) != 0 || cs.GetNbPublicVariables() != 2 {
					t.Fatal("GKR does not match SPP's single private BSB22 commitment verifier")
				}
				t.Logf("GKR_COMMITMENT inputs=%d commitments=%d committed_public=0 vk_ic=%d private_committed=%d", n, len(commitments), cs.GetNbPublicVariables()+len(commitments), len(commitments[0].PrivateCommitted))
			}
			if os.Getenv("GKR_COMPILE_ONLY") != "" {
				return
			}
			if path := os.Getenv("GKR_BASELINE_KEY"); !accelerated && path != "" {
				expected := constraintDigest(t, cs)
				cs = nil
				debug.FreeOSMemory()
				start = time.Now()
				system, err := common.ReadSystemFromFile(path)
				if err != nil {
					t.Fatal(err)
				}
				ps, ok := system.(*common.TransferProofSystem)
				if !ok || ps.NInputs != uint32(n) || ps.NOutputs != 2 {
					t.Fatal("baseline key has the wrong shape")
				}
				if actual := constraintDigest(t, ps.ConstraintSystem); actual != expected {
					t.Fatalf("baseline key circuit mismatch: %s != %s", actual, expected)
				}
				t.Logf("GKR_PAYMENT_KEY inputs=%d load_and_validate_ms=%d digest=%s", n, time.Since(start).Milliseconds(), expected)
				provePayment(t, "gkr_false", n, 2, ps.ConstraintSystem, ps.ProvingKey, ps.VerifyingKey, w)
				return
			}
			start = time.Now()
			pk, vk, err := groth16.Setup(cs)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("GKR_PAYMENT_SETUP inputs=%d gkr=%t setup_ms=%d", n, accelerated, time.Since(start).Milliseconds())
			provePayment(t, fmt.Sprintf("gkr_%t", accelerated), n, 2, cs, pk, vk, w)
		})
		debug.FreeOSMemory()
	}
}
