package tee

import "testing"

// keyPath is the derivation path dstack's KMS derives the HPKE secret from,
// not a Go import path: changing it rotates every deployment's HPKE key and
// clients pinned to the old one reject attestation with HpkeKeyMismatch. The
// fake guest compares against keyPath itself, so only a literal pins it.
func TestDstackKeyPathIsStable(t *testing.T) {
	if keyPath != "zolana/prover/hpke/v1" {
		t.Fatalf("dstack key path changed to %q; this rotates the prover's HPKE key", keyPath)
	}
}
