package backend

import (
	"fmt"
	"sync"
	"time"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"zolana/prover/prover/timing"
)

var (
	batchProofs   = promauto.NewHistogram(prometheus.HistogramOpts{Name: "prover_backend_batch_proofs", Help: "Proofs per batched engine call", Buckets: prometheus.LinearBuckets(1, 1, 16)})
	batchFailures = promauto.NewCounter(prometheus.CounterOpts{Name: "prover_backend_batch_failures_total", Help: "Proof batches retried one proof at a time"})
)

type batcher struct {
	engine batchProver
	window time.Duration
	max    int
	// Held across every engine call.
	turn chan struct{}
	mu   sync.Mutex
	open map[batchKey]*batch
}

type batchKey struct {
	ccs constraint.ConstraintSystem
	key groth16.ProvingKey
}

type batch struct {
	key     batchKey
	members []*member
	full    chan struct{}
	started chan struct{}
}

type member struct {
	witness witness.Witness
	proof   groth16.Proof
	err     error
	retry   bool
	done    chan struct{}
}

func newBatcher(engine batchProver, options Options) *batcher {
	return &batcher{
		engine: engine,
		window: options.BatchWindow,
		max:    options.BatchMax,
		turn:   make(chan struct{}, 1),
		open:   make(map[batchKey]*batch),
	}
}

func (b *batcher) prove(trace *timing.Trace, ccs constraint.ConstraintSystem, key groth16.ProvingKey, full witness.Witness) (groth16.Proof, error) {
	if hasCommitments(ccs) {
		defer trace.Start("prove")()
		return b.alone(ccs, key, full)
	}
	finishWait := trace.Start("batch")
	group, self, leads := b.join(batchKey{ccs, key}, full)
	if leads {
		b.dispatch(group)
	}
	<-group.started
	finishWait()
	finishProve := trace.Start("prove")
	if leads {
		b.run(group)
	}
	<-self.done
	finishProve()
	if !self.retry {
		return self.proof, self.err
	}
	defer trace.Start("retry")()
	// The engine evicts its prepared key on every failed proof.
	if err := ccs.IsSolved(full); err != nil {
		return nil, err
	}
	return b.alone(ccs, key, full)
}

func (b *batcher) join(key batchKey, full witness.Witness) (group *batch, self *member, leads bool) {
	self = &member{witness: full, done: make(chan struct{})}
	b.mu.Lock()
	defer b.mu.Unlock()
	group, joined := b.open[key]
	if !joined {
		group = &batch{key: key, full: make(chan struct{}), started: make(chan struct{})}
		b.open[key] = group
	}
	group.members = append(group.members, self)
	if len(group.members) == b.max {
		delete(b.open, key)
		close(group.full)
	}
	return group, self, !joined
}

func (b *batcher) dispatch(group *batch) {
	window := time.NewTimer(b.window)
	defer window.Stop()
	select {
	case <-window.C:
	case <-group.full:
	}
	b.turn <- struct{}{}
	b.mu.Lock()
	if b.open[group.key] == group {
		delete(b.open, group.key)
	}
	b.mu.Unlock()
	close(group.started)
}

func (b *batcher) run(group *batch) {
	defer func() { <-b.turn }()
	batchProofs.Observe(float64(len(group.members)))
	if len(group.members) == 1 {
		self := group.members[0]
		defer close(self.done)
		self.proof, self.err = b.engine.Prove(group.key.ccs, group.key.key, self.witness)
		return
	}
	proofs, err := b.proveBatch(group)
	if err != nil {
		batchFailures.Inc()
	}
	for index, peer := range group.members {
		if err != nil {
			peer.retry = true
		} else {
			peer.proof = proofs[index]
		}
		close(peer.done)
	}
}

// A panic fails the batch and resurfaces in the retry of its own request.
func (b *batcher) proveBatch(group *batch) (proofs []groth16.Proof, err error) {
	defer func() {
		if cause := recover(); cause != nil {
			proofs, err = nil, fmt.Errorf("proof batch panicked: %v", cause)
		}
	}()
	witnesses := make([]witness.Witness, len(group.members))
	for index, peer := range group.members {
		witnesses[index] = peer.witness
	}
	proofs, err = b.engine.ProveBatch(group.key.ccs, group.key.key, witnesses)
	if err == nil && len(proofs) != len(witnesses) {
		err = fmt.Errorf("proof batch returned %d proofs for %d witnesses", len(proofs), len(witnesses))
	}
	return proofs, err
}

func (b *batcher) alone(ccs constraint.ConstraintSystem, key groth16.ProvingKey, full witness.Witness) (groth16.Proof, error) {
	b.turn <- struct{}{}
	defer func() { <-b.turn }()
	return b.engine.Prove(ccs, key, full)
}

// ProveBatch rejects a circuit with commitments.
func hasCommitments(ccs constraint.ConstraintSystem) bool {
	commitments := ccs.GetCommitments()
	return commitments != nil && len(commitments.CommitmentIndexes()) > 0
}
