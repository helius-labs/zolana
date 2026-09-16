package directspend_test

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	direct "zolana/prover/circuits/direct_spend"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover/common"
)

func TestWideCompactPaymentProving(t *testing.T) {
	path := os.Getenv("COMPACT_BASELINE_KEY")
	if path == "" {
		t.Skip("set COMPACT_BASELINE_KEY to an existing direct-payment_512_2.key")
	}
	t.Logf("go=%s arch=%s cpus=%d gomaxprocs=%d", runtime.Version(), runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0))
	t.Run("original", func(t *testing.T) {
		start := time.Now()
		compiled, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, direct.NewPayment(512, 2), frontend.WithCompressThreshold(300))
		if err != nil {
			t.Fatal(err)
		}
		expected := constraintDigest(t, compiled)
		t.Logf("WIDE_SETUP mode=original compile_ms=%d digest=%s", time.Since(start).Milliseconds(), expected)
		compiled = nil
		debug.FreeOSMemory()
		start = time.Now()
		system, err := common.ReadSystemFromFile(path)
		if err != nil {
			t.Fatal(err)
		}
		ps, ok := system.(*common.TransferProofSystem)
		if !ok || ps.NInputs != 512 || ps.NOutputs != 2 {
			t.Fatal("baseline key has the wrong shape")
		}
		if actual := constraintDigest(t, ps.ConstraintSystem); actual != expected {
			t.Fatalf("baseline key circuit mismatch: %s != %s", actual, expected)
		}
		t.Logf("WIDE_SETUP mode=original load_and_validate_ms=%d", time.Since(start).Milliseconds())
		w := payment(t, 512, 512)
		addSecondOutput(t, w)
		provePayment(t, "original", 512, 2, ps.ConstraintSystem, ps.ProvingKey, ps.VerifyingKey, w)
	})
	debug.FreeOSMemory()
	t.Run("subtree_external_admission", func(t *testing.T) {
		c, w := newCompactPayment(512, true), compactWitness(t, 512, true)
		c.Balance.Outputs = make([]direct.Output, 2)
		c.ExternalAdmission, w.ExternalAdmission = true, true
		c.Freshness.Witnesses, w.Freshness.Witnesses = nil, nil
		addSecondOutput(t, w.PaymentCircuit)
		start := time.Now()
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
		if err != nil {
			t.Fatal(err)
		}
		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("WIDE_SETUP mode=subtree_external_admission compile_and_setup_ms=%d constraints=%d", time.Since(start).Milliseconds(), ccs.GetNbConstraints())
		provePayment(t, "subtree_external_admission", 512, 2, ccs, pk, vk, w)
	})
}

func constraintDigest(t *testing.T, cs constraint.ConstraintSystem) string {
	t.Helper()
	copy := *cs.(*csbn254.R1CS)
	copy.Logs, copy.DebugInfo, copy.MDebug = nil, nil, nil
	copy.SymbolTable = csbn254.NewR1CS(0).SymbolTable
	digest := sha256.New()
	if _, err := copy.WriteTo(digest); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", digest.Sum(nil))
}

func addSecondOutput(t *testing.T, w *direct.PaymentCircuit) {
	t.Helper()
	outputHash, err := protocol.UtxoHash(protocol.Utxo{
		Domain: big.NewInt(protocol.UtxoDomain), Owner: hash(t, 43, 47), Asset: big.NewInt(1),
		Amount: big.NewInt(0), Blinding: big.NewInt(54), DataHash: big.NewInt(0),
		RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0),
	}, big.NewInt(11))
	if err != nil {
		t.Fatal(err)
	}
	w.Balance.Outputs = append(w.Balance.Outputs, direct.Output{OwnerKey: 43, NullifierPK: 47, Amount: 0, Blinding: 54, Hash: outputHash})
	bindPayment(t, w)
}

func provePayment(t *testing.T, mode string, inputs, outputs int, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, assignment frontend.Circuit) {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	public, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		start := time.Now()
		proof, err := groth16.Prove(ccs, pk, witness)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatal(err)
		}
		if err := groth16.Verify(proof, vk, public); err != nil {
			t.Fatal(err)
		}
		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		t.Logf("PAYMENT_PROVE mode=%s inputs=%d outputs=%d trial=%d constraints=%d prove_ms=%.3f heap_bytes=%d", mode, inputs, outputs, i, ccs.GetNbConstraints(), float64(elapsed.Microseconds())/1000, memory.HeapAlloc)
	}
}
