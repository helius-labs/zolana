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
// keys (interface + tree crates), regenerates proving-keys.lock,
// and uploads the keys to a new immutable version folder in S3. Only then update
// the pinned values below (UPDATE_FINGERPRINTS=1 prints the current ones).
package fingerprint

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark/constraint"

	"github.com/helius-labs/zolana/prover/server/prover/common"
	customring "github.com/helius-labs/zolana/prover/server/prover/custom_ring"
	mergeprover "github.com/helius-labs/zolana/prover/server/prover/merge"
	nulltree "github.com/helius-labs/zolana/prover/server/prover/nullifier_tree"
	eddsaprover "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa"
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

	eddsa, err := eddsaprover.R1CSTransfer(2, 4, eddsaprover.ConfidentialVariant)
	add("transfer_confidential_2_4", eddsa, err)

	ring, err := eddsaprover.R1CSTransfer(2, 4, eddsaprover.RingVariant)
	add("transfer_ring_2_4", ring, err)

	ringAuthority, err := eddsaprover.R1CSTransfer(2, 2, eddsaprover.RingAuthorityVariant)
	add("transfer_ring_authority_2_2", ringAuthority, err)

	anonymousRing, err := eddsaprover.R1CSAnonymousEddsaTransfer(2, 4)
	add("transfer_eddsa_ring_2_4", anonymousRing, err)

	// One key per family, TestRingKeyCatalog pins every ring key.
	families := map[common.RingFamily]bool{}
	for _, key := range common.RingKeys {
		if families[key.Family] {
			continue
		}
		families[key.Family] = true
		ring, err := customring.Ring(key.Circuit)
		if err != nil {
			t.Fatal(err)
		}
		cs, err := ring.R1CS()
		add(strings.TrimSuffix(common.RingKeyFile(key.Circuit), ".key"), cs, err)
	}

	merged, err := mergeprover.R1CSMerge(24)
	add("merge_24_1", merged, err)

	mergedRing, err := mergeprover.R1CSMergeRing(24)
	add("merge_ring_24_1", mergedRing, err)

	batch, err := nulltree.R1CSBatchAddressAppend(40, 10)
	add("batch_address-append_40_10", batch, err)

	return out
}

// Pinned to the current key set; the version hash is in
// prover/server/prover/provingkeys/proving-keys.lock. Regenerate with
// UPDATE_FINGERPRINTS=1 after a full key rotation.
var expectedFingerprints = map[string]fingerprint{
	"batch_address-append_40_10":            {constraints: 421991, public: 2},
	"custom_ring_apply_records_1":           {constraints: 15492, public: 2},
	"custom_ring_audit_anonymous_4_2":       {constraints: 123527, public: 2},
	"custom_ring_audit_anonymous_entry_8_2": {constraints: 138067, public: 2},
	"custom_ring_audit_delivered_8":         {constraints: 284405, public: 2},
	"custom_ring_audit_packed_2":            {constraints: 53502, public: 2},
	"custom_ring_deposit":                   {constraints: 148936, public: 2},
	"custom_ring_merge_anonymous_8":         {constraints: 56192, public: 2},
	"custom_ring_policy_delegate_1x2":       {constraints: 48736, public: 2},
	"custom_ring_policy_member_2":           {constraints: 48455, public: 2},
	"custom_ring_register_key":              {constraints: 36991, public: 2},
	"merge_24_1":                            {constraints: 527688, public: 2},
	"merge_ring_24_1":                       {constraints: 531750, public: 2},
	"transfer_confidential_2_4":             {constraints: 57558, public: 2},
	"transfer_eddsa_ring_2_4":               {constraints: 129120, public: 2},
	"transfer_ring_2_4":                     {constraints: 57708, public: 2},
	"transfer_ring_authority_2_2":           {constraints: 51925, public: 2},
}

func TestCircuitFingerprintsMatchRotatedKeys(t *testing.T) {
	got := compileFingerprints(t)

	if os.Getenv("UPDATE_FINGERPRINTS") == "1" {
		for name, fp := range got {
			fmt.Printf("\t%q: {constraints: %d, public: %d},\n", name, fp.constraints, fp.public)
		}
		t.Skip("UPDATE_FINGERPRINTS=1: printed current fingerprints; paste into expectedFingerprints")
	}

	for name := range got {
		if _, ok := expectedFingerprints[name]; !ok {
			t.Errorf("circuit %s has no pinned fingerprint", name)
		}
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
