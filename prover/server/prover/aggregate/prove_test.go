//go:build aggregate_keys

package aggregate

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"zolana/prover/prover/common"

	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

// The aggregate keys are unpublished and gitignored, so every machine
// generates its own with scripts/generate_keys_aggregate.sh. The build tag
// keeps these out of the default tier rather than skipping them at run time.
func keysDir() string {
	if dir := os.Getenv("ZOLANA_SPP_KEYS_DIR"); dir != "" {
		return dir
	}
	return filepath.Join("..", "..", "proving-keys")
}

func loadAggregateSystem(t *testing.T, p Params) *common.AggregateProofSystem {
	t.Helper()
	path := filepath.Join(keysDir(), p.KeyName())
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("missing %s, generate it with scripts/generate_keys_aggregate.sh", path)
	}
	system, err := common.ReadSystemFromFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	ps, ok := system.(*common.AggregateProofSystem)
	if !ok {
		t.Fatalf("%s read as %T", path, system)
	}
	return ps
}

// The header is what the key loader trusts over the file name, so a key must
// decode with the slots it was written for.
func TestAggregateKeyHeaderRoundTrips(t *testing.T) {
	params := p256Params(2)
	ps := loadAggregateSystem(t, params)

	if !slices.Equal(ps.Slots, params.Slots) {
		t.Errorf("slots decode as %s, want %s", ps.KeyName(), params.KeyName())
	}
}

// A mixed key writes the slot-list header, so it must decode to the same
// ordered slots, take slot included.
func TestMixedAggregateKeyHeaderRoundTrips(t *testing.T) {
	params := Params{Slots: []common.AggregateSlot{takeSlot(), confidentialSlot()}}
	ps := loadAggregateSystem(t, params)

	if !slices.Equal(ps.Slots, params.Slots) {
		t.Errorf("slots decode as %s, want %s", ps.KeyName(), params.KeyName())
	}
}

// The outer key must be the shape the shielded pool already verifies, one
// public input and one BSB22 commitment over private wires. Then the
// aggregate needs no new on-chain verifier, and groth16_solana parses the key
// with the same generator the transfer rails use.
func TestAggregateVerifyingKeyMatchesTheOnChainVerifier(t *testing.T) {
	ps := loadAggregateSystem(t, p256Params(2))

	vk, ok := ps.VerifyingKey.(*groth16bn254.VerifyingKey)
	if !ok {
		t.Fatalf("verifying key is %T", ps.VerifyingKey)
	}
	if len(vk.CommitmentKeys) != 1 {
		t.Fatalf("outer key has %d commitments, want 1", len(vk.CommitmentKeys))
	}
	// An empty committed set means the commitment covers private wires only.
	// The groth16_solana parser rejects a commitment over a public input.
	if committed := vk.PublicAndCommitmentCommitted; len(committed) != 1 || len(committed[0]) != 0 {
		t.Errorf("commitment covers public inputs %v, want none", committed)
	}

	// NbPublicWitness counts the commitment wire gnark appends, so the circuit's
	// own public inputs are what remains. The outer circuit declares one, the
	// aggregate hash.
	declared := ps.VerifyingKey.NbPublicWitness() - len(vk.CommitmentKeys)
	if declared != 1 {
		t.Errorf("outer key declares %d public inputs, want 1", declared)
	}

	// groth16_solana requires vk_ic.len() == public_inputs + 2 for a BSB22 key.
	// The columns are the constant, one per public input, and one for the
	// commitment-derived wire. This is the same shape as the P256 rail's key,
	// so the aggregate needs no new verifier.
	if want := declared + 2; len(vk.G1.K) != want {
		t.Errorf("outer key has %d IC points, want %d", len(vk.G1.K), want)
	}
}

// Proving needs a real batch of inner proofs. Building an SPP witness needs the
// wallet and tree machinery the prover packages must not depend on, so the
// batch-proving path is exercised end to end from the SDK instead.
func TestProveAggregateRejectsAWrongLegCount(t *testing.T) {
	ps := loadAggregateSystem(t, p256Params(2))

	for _, count := range []int{0, 1, 3} {
		_, err := ProveAggregate(ps, make([]Leg, count))
		if err == nil {
			t.Errorf("%d legs were accepted against a batch of %d", count, ps.Batch())
			continue
		}
		if want := fmt.Sprintf("%d legs against a batch of %d", count, ps.Batch()); err.Error() != want {
			t.Errorf("error is %q, want %q", err, want)
		}
	}
}
