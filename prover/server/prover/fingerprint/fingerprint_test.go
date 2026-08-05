package fingerprint

import (
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark/constraint"

	mergeprover "zolana/prover/prover/merge"
	nulltree "zolana/prover/prover/nullifier_tree"
	eddsaprover "zolana/prover/prover/transfer_eddsa_only"
)

// Representative circuit per distinct constraint profile, keyed by proving-key
// name so the fingerprints line up with Pinned. The other transfer shapes share
// the same gadget bodies as the entries below, so a gadget-level change (the
// #113 class of break) trips at least these fingerprints. Keep this set small:
// gnark compilation is expensive.
func compileFingerprints(t *testing.T) map[string]Fingerprint {
	t.Helper()
	out := make(map[string]Fingerprint)

	add := func(name string, cs constraint.ConstraintSystem, err error) {
		if err != nil {
			t.Fatalf("compile %s: %v", name, err)
		}
		out[name] = Fingerprint{
			Constraints: cs.GetNbConstraints(),
			Public:      cs.GetNbPublicVariables(),
		}
	}

	eddsa, err := eddsaprover.R1CSTransfer(2, 3, eddsaprover.ConfidentialVariant)
	add("transfer_confidential_2_3", eddsa, err)

	zone, err := eddsaprover.R1CSTransfer(2, 3, eddsaprover.ZoneVariant)
	add("transfer_zone_2_3", zone, err)

	zoneAuthority, err := eddsaprover.R1CSTransfer(2, 2, eddsaprover.ZoneAuthorityVariant)
	add("transfer_zone_authority_2_2", zoneAuthority, err)

	p256Zone, err := eddsaprover.R1CSP256Transfer(2, 3)
	add("transfer_p256_zone_2_3", p256Zone, err)

	merged, err := mergeprover.R1CSMerge()
	add("merge_8_1", merged, err)

	mergedZone, err := mergeprover.R1CSMergeZone()
	add("merge_zone_8_1", mergedZone, err)

	batch, err := nulltree.R1CSBatchAddressAppend(40, 10)
	add("batch_address-append_40_10", batch, err)

	return out
}

// The key-side fingerprints must differ from the source-side ones only where
// KnownKeyDrift says so, and by exactly the recorded amount.
func TestKnownKeyDriftIsComplete(t *testing.T) {
	for name, keyFingerprint := range KeyPinned {
		source, ok := Pinned[name]
		if !ok {
			t.Errorf("KeyPinned has %s but Pinned does not", name)
			continue
		}
		delta := keyFingerprint.Constraints - source.Constraints
		recorded, drifted := KnownKeyDrift[name]
		switch {
		case delta == 0 && drifted:
			t.Errorf("%s no longer drifts: remove it from KnownKeyDrift", name)
		case delta != 0 && !drifted:
			t.Errorf(
				"%s drifted by %d constraints (key %d, source %d) and is not in KnownKeyDrift. "+
					"Either the circuit changed without a key rotation or the drift is new; "+
					"see the KeyPinned doc comment.",
				name, delta, keyFingerprint.Constraints, source.Constraints,
			)
		case delta != recorded:
			t.Errorf("%s drift changed: got %d constraints, KnownKeyDrift records %d", name, delta, recorded)
		}
		if keyFingerprint.Public != source.Public {
			t.Errorf(
				"%s public variable count differs (key %d, source %d): the witness layout changed, "+
					"so this key cannot prove current witnesses at all",
				name, keyFingerprint.Public, source.Public,
			)
		}
	}
	for name := range KnownKeyDrift {
		if _, ok := KeyPinned[name]; !ok {
			t.Errorf("KnownKeyDrift lists %s, which has no KeyPinned entry", name)
		}
	}
}

func TestCircuitFingerprintsMatchRotatedKeys(t *testing.T) {
	got := compileFingerprints(t)

	if os.Getenv("UPDATE_FINGERPRINTS") == "1" {
		for name, fp := range got {
			fmt.Printf("\t%q: {Constraints: %d, Public: %d},\n", name, fp.Constraints, fp.Public)
		}
		t.Skip("UPDATE_FINGERPRINTS=1: printed current fingerprints; paste into Pinned")
	}

	for name, want := range Pinned {
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
					"update Pinned (UPDATE_FINGERPRINTS=1 prints the values).",
				name, want.Constraints, have.Constraints, want.Public, have.Public,
			)
		}
	}
}
