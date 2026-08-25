// Package fingerprint guards against silent circuit drift: if a circuit's
// constraint system changes without the proving/verifying keys being rotated,
// every proof breaks (wrong witness size against stale keys, or a stale
// on-chain verifying key rejecting a fresh proof). #113 shipped exactly that.
//
// Each representative circuit is compiled and fingerprinted by its constraint
// and public-variable counts. A change here means the circuit changed; the fix
// is NOT to blindly update these numbers but to run the full rotation:
//
//	prover/server/scripts/rotate_proving_keys.sh
//
// which regenerates proving keys, regenerates and commits the Rust verifying
// keys (interface + batched-merkle-tree crates), regenerates proving-keys.lock,
// and uploads the keys to a new immutable version folder in S3. Only then update
// the pinned values below (UPDATE_FINGERPRINTS=1 prints the current ones).
package fingerprint

import (
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark/constraint"

	customring "zolana/prover/prover/custom_ring"
	mergeprover "zolana/prover/prover/merge"
	nulltree "zolana/prover/prover/nullifier_tree"
	eddsaprover "zolana/prover/prover/transfer_eddsa_only"
)

type fingerprint struct {
	constraints int
	public      int
}

// Representative circuit per distinct constraint profile. The other transfer
// shapes share the same gadget bodies as the entries below, so a gadget-level
// change (the #113 class of break) trips at least these fingerprints. Keep this
// set small: gnark compilation is expensive.
func compileFingerprints(t *testing.T) map[string]fingerprint {
	t.Helper()
	out := make(map[string]fingerprint)

	add := func(name string, cs constraint.ConstraintSystem, err error) {
		if err != nil {
			t.Fatalf("compile %s: %v", name, err)
		}
		out[name] = fingerprint{
			constraints: cs.GetNbConstraints(),
			public:      cs.GetNbPublicVariables(),
		}
	}

	eddsa, err := eddsaprover.R1CSTransfer(2, 3, eddsaprover.ConfidentialVariant)
	add("transfer_confidential_2_3", eddsa, err)

	ring, err := eddsaprover.R1CSTransfer(2, 3, eddsaprover.RingVariant)
	add("transfer_ring_2_3", ring, err)

	ringAuthority, err := eddsaprover.R1CSTransfer(2, 2, eddsaprover.RingAuthorityVariant)
	add("transfer_ring_authority_2_2", ringAuthority, err)

	p256Ring, err := eddsaprover.R1CSP256Transfer(2, 3)
	add("transfer_p256_ring_2_3", p256Ring, err)

	audit, err := customring.R1CSCustomRingAudit()
	add("custom_ring_audit_transfer", audit, err)

	policy, err := customring.R1CSCustomRingPolicy()
	add("custom_ring_policy_transfer", policy, err)

	merged, err := mergeprover.R1CSMerge()
	add("merge_8_1", merged, err)

	mergedRing, err := mergeprover.R1CSMergeRing()
	add("merge_ring_8_1", mergedRing, err)

	batch, err := nulltree.R1CSBatchAddressAppend(40, 10)
	add("batch_address-append_40_10", batch, err)

	return out
}

// Pinned to the current key set; the version hash is in
// prover/server/prover/provingkeys/proving-keys.lock. Regenerate with
// UPDATE_FINGERPRINTS=1 after a full key rotation.
var expectedFingerprints = map[string]fingerprint{
	"transfer_confidential_2_3":   {constraints: 54031, public: 2},
	"transfer_ring_2_3":           {constraints: 54136, public: 2},
	"transfer_ring_authority_2_2": {constraints: 50574, public: 2},
	"transfer_p256_ring_2_3":      {constraints: 245645, public: 2},
	"custom_ring_audit_transfer":  {constraints: 327883, public: 2},
	"custom_ring_policy_transfer": {constraints: 583132, public: 2},
	"merge_8_1":                   {constraints: 180470, public: 2},
	"merge_ring_8_1":              {constraints: 180740, public: 2},
	"batch_address-append_40_10":  {constraints: 423683, public: 2},
}

func TestCircuitFingerprintsMatchRotatedKeys(t *testing.T) {
	got := compileFingerprints(t)

	if os.Getenv("UPDATE_FINGERPRINTS") == "1" {
		for name, fp := range got {
			fmt.Printf("\t%q: {constraints: %d, public: %d},\n", name, fp.constraints, fp.public)
		}
		t.Skip("UPDATE_FINGERPRINTS=1: printed current fingerprints; paste into expectedFingerprints")
	}

	for name, want := range expectedFingerprints {
		have, ok := got[name]
		if !ok {
			t.Errorf("missing fingerprint for %s", name)
			continue
		}
		if have != want {
			t.Errorf(
				"circuit %s changed (constraints %d->%d, public %d->%d).\n"+
					"Circuit changes require a key rotation: run "+
					"prover/server/scripts/rotate_proving_keys.sh <new-tag>, then "+
					"update expectedFingerprints (UPDATE_FINGERPRINTS=1 prints the values).",
				name, want.constraints, have.constraints, want.public, have.public,
			)
		}
	}
}
