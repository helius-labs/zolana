package backend

import (
	"errors"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/prover/timing"
)

type square struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *square) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

type committedSquare struct{ square }

func (c *committedSquare) Define(api frontend.API) error {
	commitment, err := api.(frontend.Committer).Commit(c.X)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)
	return c.square.Define(api)
}

var errBadWitness = errors.New("bad witness")

type fakeEngine struct {
	proofs  map[witness.Witness]groth16.Proof
	bad     witness.Witness
	panics  bool
	entered chan struct{}
	gate    chan struct{}
	active  atomic.Int32
	mu      sync.Mutex
	batches []int
	singles int
}

func newFakeEngine(t *testing.T, count int) (*fakeEngine, []witness.Witness) {
	t.Helper()
	engine := &fakeEngine{proofs: make(map[witness.Witness]groth16.Proof)}
	witnesses := make([]witness.Witness, count)
	for index := range witnesses {
		witnesses[index] = squareWitness(t, index+2, (index+2)*(index+2))
		engine.proofs[witnesses[index]] = &groth16bn254.Proof{}
	}
	return engine, witnesses
}

func squareWitness(t *testing.T, x, y int) witness.Witness {
	t.Helper()
	full, err := frontend.NewWitness(&square{X: x, Y: y}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return full
}

func (f *fakeEngine) enter(t *testing.T) func() {
	if f.active.Add(1) != 1 {
		t.Error("engine calls overlapped")
	}
	return func() { f.active.Add(-1) }
}

func (f *fakeEngine) Prove(_ constraint.ConstraintSystem, _ groth16.ProvingKey, full witness.Witness) (groth16.Proof, error) {
	f.mu.Lock()
	f.singles++
	f.mu.Unlock()
	if f.entered != nil {
		f.entered <- struct{}{}
		<-f.gate
	}
	if full == f.bad {
		if f.panics {
			panic(errBadWitness)
		}
		return nil, errBadWitness
	}
	return f.proofs[full], nil
}

func (f *fakeEngine) ProveBatch(_ constraint.ConstraintSystem, _ groth16.ProvingKey, witnesses []witness.Witness) ([]groth16.Proof, error) {
	f.mu.Lock()
	f.batches = append(f.batches, len(witnesses))
	f.mu.Unlock()
	proofs := make([]groth16.Proof, len(witnesses))
	for index, full := range witnesses {
		if full == f.bad {
			if f.panics {
				panic(errBadWitness)
			}
			return nil, errBadWitness
		}
		proofs[index] = f.proofs[full]
	}
	return proofs, nil
}

func (f *fakeEngine) Close() error { return nil }

func (f *fakeEngine) calls() ([]int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.batches), f.singles
}

type serialEngine struct {
	*fakeEngine
	t *testing.T
}

func (s serialEngine) Prove(ccs constraint.ConstraintSystem, key groth16.ProvingKey, full witness.Witness) (groth16.Proof, error) {
	defer s.enter(s.t)()
	return s.fakeEngine.Prove(ccs, key, full)
}

func (s serialEngine) ProveBatch(ccs constraint.ConstraintSystem, key groth16.ProvingKey, witnesses []witness.Witness) ([]groth16.Proof, error) {
	defer s.enter(s.t)()
	return s.fakeEngine.ProveBatch(ccs, key, witnesses)
}

type outcome struct {
	proof    groth16.Proof
	err      error
	panicked any
}

func proveEach(b *batcher, ccs constraint.ConstraintSystem, witnesses []witness.Witness) []outcome {
	outcomes := make([]outcome, len(witnesses))
	var requests sync.WaitGroup
	for index, full := range witnesses {
		requests.Go(func() {
			defer func() { outcomes[index].panicked = recover() }()
			outcomes[index].proof, outcomes[index].err = b.prove(nil, ccs, nil, full)
		})
	}
	requests.Wait()
	return outcomes
}

func assertOwnProofs(t *testing.T, engine *fakeEngine, witnesses []witness.Witness, outcomes []outcome) {
	t.Helper()
	for index, full := range witnesses {
		if outcomes[index].err != nil || outcomes[index].panicked != nil || outcomes[index].proof != engine.proofs[full] {
			t.Fatalf("request %d got %+v", index, outcomes[index])
		}
	}
}

func TestBatchCoalescesInWitnessOrder(t *testing.T) {
	engine, witnesses := newFakeEngine(t, 4)
	b := newBatcher(serialEngine{engine, t}, Options{BatchWindow: time.Minute, BatchMax: 4})
	outcomes := proveEach(b, compile(t, &square{}), witnesses)
	assertOwnProofs(t, engine, witnesses, outcomes)
	if batches, singles := engine.calls(); !slices.Equal(batches, []int{4}) || singles != 0 {
		t.Fatalf("batches %v singles %d", batches, singles)
	}
}

func TestBatchWindowClosesPartialBatch(t *testing.T) {
	engine, witnesses := newFakeEngine(t, 3)
	const window = 50 * time.Millisecond
	b := newBatcher(serialEngine{engine, t}, Options{BatchWindow: window, BatchMax: 8})
	started := time.Now()
	assertOwnProofs(t, engine, witnesses, proveEach(b, compile(t, &square{}), witnesses))
	if time.Since(started) < window {
		t.Fatal("batch closed before its window")
	}
	if batches, singles := engine.calls(); !slices.Equal(batches, []int{3}) || singles != 0 {
		t.Fatalf("batches %v singles %d", batches, singles)
	}
}

func TestBatchMaxSplitsRequests(t *testing.T) {
	engine, witnesses := newFakeEngine(t, 5)
	b := newBatcher(serialEngine{engine, t}, Options{BatchWindow: time.Second, BatchMax: 2})
	assertOwnProofs(t, engine, witnesses, proveEach(b, compile(t, &square{}), witnesses))
	if batches, singles := engine.calls(); !slices.Equal(batches, []int{2, 2}) || singles != 1 {
		t.Fatalf("batches %v singles %d", batches, singles)
	}
}

func TestBatchCollectsWhileEngineIsBusy(t *testing.T) {
	engine, witnesses := newFakeEngine(t, 4)
	engine.entered, engine.gate = make(chan struct{}), make(chan struct{})
	b := newBatcher(serialEngine{engine, t}, Options{BatchMax: 8})
	ccs := compile(t, &square{})
	first := make(chan []outcome)
	go func() { first <- proveEach(b, ccs, witnesses[:1]) }()
	<-engine.entered
	rest := make(chan []outcome)
	go func() { rest <- proveEach(b, ccs, witnesses[1:]) }()
	for waiting := 0; waiting != 3; {
		b.mu.Lock()
		waiting = 0
		for _, group := range b.open {
			waiting += len(group.members)
		}
		b.mu.Unlock()
		runtime.Gosched()
	}
	close(engine.gate)
	assertOwnProofs(t, engine, witnesses[:1], <-first)
	assertOwnProofs(t, engine, witnesses[1:], <-rest)
	if batches, singles := engine.calls(); !slices.Equal(batches, []int{3}) || singles != 1 {
		t.Fatalf("batches %v singles %d", batches, singles)
	}
}

func TestBatchesSeparateProvingKeys(t *testing.T) {
	engine, witnesses := newFakeEngine(t, 4)
	b := newBatcher(serialEngine{engine, t}, Options{BatchWindow: 100 * time.Millisecond, BatchMax: 4})
	first, second := compile(t, &square{}), compile(t, &square{})
	var requests sync.WaitGroup
	outcomes := make([][]outcome, 2)
	for index, ccs := range []constraint.ConstraintSystem{first, second} {
		requests.Go(func() { outcomes[index] = proveEach(b, ccs, witnesses[2*index:2*index+2]) })
	}
	requests.Wait()
	assertOwnProofs(t, engine, witnesses[:2], outcomes[0])
	assertOwnProofs(t, engine, witnesses[2:], outcomes[1])
	if batches, singles := engine.calls(); !slices.Equal(batches, []int{2, 2}) || singles != 0 {
		t.Fatalf("batches %v singles %d", batches, singles)
	}
}

func TestBatchFailureIsolatesEachRequest(t *testing.T) {
	for _, failure := range []struct {
		name     string
		solvable bool
		panics   bool
		singles  int
	}{
		{"unsolvable witness", false, false, 2},
		{"engine error", true, false, 3},
		{"engine panic", true, true, 3},
	} {
		t.Run(failure.name, func(t *testing.T) {
			engine, witnesses := newFakeEngine(t, 3)
			if !failure.solvable {
				witnesses[1] = squareWitness(t, 3, 10)
			}
			engine.bad, engine.panics = witnesses[1], failure.panics
			b := newBatcher(serialEngine{engine, t}, Options{BatchWindow: time.Minute, BatchMax: 3})
			outcomes := proveEach(b, compile(t, &square{}), witnesses)
			assertOwnProofs(t, engine, []witness.Witness{witnesses[0], witnesses[2]}, []outcome{outcomes[0], outcomes[2]})
			bad := outcomes[1]
			switch {
			case bad.proof != nil:
				t.Fatalf("bad request got a proof %+v", bad)
			case failure.panics && bad.panicked != errBadWitness:
				t.Fatalf("bad request got %+v", bad)
			case !failure.panics && (bad.err == nil || errors.Is(bad.err, errBadWitness) != failure.solvable):
				t.Fatalf("bad request got %+v", bad)
			}
			if batches, singles := engine.calls(); !slices.Equal(batches, []int{3}) || singles != failure.singles {
				t.Fatalf("batches %v singles %d", batches, singles)
			}
		})
	}
}

func TestCommitmentCircuitsBypassBatching(t *testing.T) {
	engine, witnesses := newFakeEngine(t, 3)
	b := newBatcher(serialEngine{engine, t}, Options{BatchWindow: time.Minute, BatchMax: 3})
	assertOwnProofs(t, engine, witnesses, proveEach(b, compile(t, &committedSquare{}), witnesses))
	if batches, singles := engine.calls(); len(batches) != 0 || singles != 3 {
		t.Fatalf("batches %v singles %d", batches, singles)
	}
}

type gnarkBatch struct {
	cpuProver
	batches atomic.Int32
}

func (g *gnarkBatch) ProveBatch(ccs constraint.ConstraintSystem, key groth16.ProvingKey, witnesses []witness.Witness) ([]groth16.Proof, error) {
	g.batches.Add(1)
	proofs := make([]groth16.Proof, len(witnesses))
	for index, full := range witnesses {
		proof, err := groth16.Prove(ccs, key, full)
		if err != nil {
			return nil, err
		}
		proofs[index] = proof
	}
	return proofs, nil
}

func TestBatchedProofsVerify(t *testing.T) {
	resetBackend(t)
	ccs := compile(t, &square{})
	key, verifyingKey, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	engine := &gnarkBatch{}
	state.Lock()
	state.prover, state.batches, state.initialized = engine, newBatcher(engine, Options{BatchWindow: time.Minute, BatchMax: 4}), true
	state.Unlock()
	var requests sync.WaitGroup
	for value := range 4 {
		requests.Go(func() {
			assignment := &square{X: value + 2, Y: (value + 2) * (value + 2)}
			trace := timing.New()
			proof, err := ProveAssignment(trace, ccs, key, func() (frontend.Circuit, error) { return assignment, nil })
			if err != nil {
				t.Error(err)
				return
			}
			public, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
			if err != nil {
				t.Error(err)
				return
			}
			if err := groth16.Verify(proof, verifyingKey, public); err != nil {
				t.Error(err)
			}
			var names []string
			for _, span := range trace.Snapshot() {
				names = append(names, span.Name)
			}
			if !slices.Equal(names, []string{"witness", "batch", "prove", "server"}) {
				t.Errorf("spans %v", names)
			}
		})
	}
	requests.Wait()
	if engine.batches.Load() != 1 {
		t.Fatalf("%d batches proved four requests", engine.batches.Load())
	}
}

func TestGnarkBackendNeverBatches(t *testing.T) {
	resetBackend(t)
	t.Setenv("PROVER_BACKEND", "gnark")
	if err := Initialize(Options{BatchWindow: time.Millisecond, BatchMax: 4}); err != nil {
		t.Fatal(err)
	}
	if state.batches != nil {
		t.Fatal("gnark backend batched proofs")
	}
}

func TestInitializeRejectsInvalidBatching(t *testing.T) {
	for _, options := range []Options{{BatchWindow: -time.Millisecond}, {BatchWindow: 2 * maxBatchWindow}, {BatchMax: -1}} {
		resetBackend(t)
		t.Setenv("PROVER_BACKEND", "gnark")
		if err := Initialize(options); err == nil {
			t.Fatalf("accepted %+v", options)
		}
	}
}
