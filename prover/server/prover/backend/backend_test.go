package backend

import (
	"errors"
	"testing"
	"time"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

func resetBackend(t *testing.T) {
	t.Helper()
	state.Lock()
	previous, initialized := state.prover, state.initialized
	state.prover, state.initialized = cpuProver{}, false
	state.Unlock()
	t.Cleanup(func() {
		if err := Close(); err != nil {
			t.Error(err)
		}
		state.Lock()
		state.prover, state.initialized = previous, initialized
		state.Unlock()
	})
}

func TestInitializeCPU(t *testing.T) {
	for _, name := range []string{"", "gnark"} {
		t.Run(name, func(t *testing.T) {
			resetBackend(t)
			t.Setenv("PROVER_BACKEND", name)
			if err := Initialize(); err != nil {
				t.Fatal(err)
			}
			if _, ok := state.prover.(cpuProver); !ok {
				t.Fatal("CPU backend was not selected")
			}
			if err := Initialize(); err == nil {
				t.Fatal("backend was initialized twice")
			}
		})
	}
}

func TestInvalidSelectionDisablesProofs(t *testing.T) {
	resetBackend(t)
	t.Setenv("PROVER_BACKEND", "invalid")
	if err := Initialize(); err == nil {
		t.Fatal("invalid backend was accepted")
	}
	if _, err := Prove(nil, nil, nil); err == nil {
		t.Fatal("proof request reached a backend after selection failed")
	}
}

type heldProver struct {
	entered chan struct{}
	release chan struct{}
	closed  chan struct{}
	err     error
}

func (p *heldProver) Prove(constraint.ConstraintSystem, groth16.ProvingKey, witness.Witness) (groth16.Proof, error) {
	close(p.entered)
	<-p.release
	return nil, p.err
}

func (p *heldProver) Close() error {
	close(p.closed)
	return nil
}

func TestCloseDrainsProofs(t *testing.T) {
	resetBackend(t)
	p := &heldProver{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}), err: errors.New("proof stopped")}
	state.Lock()
	state.prover, state.initialized = p, true
	state.Unlock()
	proved := make(chan error, 1)
	go func() {
		_, err := Prove(nil, nil, nil)
		proved <- err
	}()
	<-p.entered
	closed := make(chan error, 1)
	go func() { closed <- Close() }()
	select {
	case <-p.closed:
		t.Error("backend closed before proof returned")
	case <-time.After(20 * time.Millisecond):
	}
	close(p.release)
	if err := <-proved; !errors.Is(err, p.err) {
		t.Fatalf("unexpected proof error %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.closed:
	default:
		t.Fatal("backend resources were not closed")
	}
	if _, err := Prove(nil, nil, nil); err == nil {
		t.Fatal("closed backend accepted a proof")
	}
	if err := Close(); err != nil {
		t.Fatal(err)
	}
}
