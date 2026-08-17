// Package fingerprint pins the constraint-system shape of every representative
// circuit, guarding against silent circuit drift: if a circuit's constraint
// system changes without the proving/verifying keys being rotated, every proof
// breaks (wrong witness size against stale keys, or a stale on-chain verifying
// key rejecting a fresh proof). #113 shipped exactly that.
//
// A change here means the circuit changed; the fix is NOT to blindly update
// these numbers but to run the full rotation:
//
//	prover/server/scripts/rotate_proving_keys.sh
//
// which regenerates proving keys, regenerates and commits the Rust verifying
// keys (interface + batched-merkle-tree crates), regenerates proving-keys.lock,
// and uploads the keys to a new immutable version folder in S3. Only then update
// the pinned values below (UPDATE_FINGERPRINTS=1 prints the current ones).
package fingerprint

// Fingerprint is one circuit's constraint and public-variable count.
type Fingerprint struct {
	Constraints int
	Public      int
}

// Pinned is the fingerprint of every representative circuit as compiled from
// the current sources, keyed by proving-key name (the key filename without its
// .key suffix). TestCircuitFingerprintsMatchRotatedKeys enforces it.
var Pinned = map[string]Fingerprint{
	"transfer_confidential_2_3":   {Constraints: 71964, Public: 2},
	"transfer_zone_2_3":           {Constraints: 72069, Public: 2},
	"transfer_zone_authority_2_2": {Constraints: 68444, Public: 2},
	"transfer_p256_zone_2_3":      {Constraints: 263578, Public: 2},
	"merge_8_1":                   {Constraints: 180470, Public: 2},
	"merge_zone_8_1":              {Constraints: 180740, Public: 2},
	"batch_address-append_40_10":  {Constraints: 423683, Public: 2},
}

// KeyPinned is the fingerprint of the constraint system embedded in each
// committed proving key, for keys whose circuit still matches these sources.
//
// It is EMPTY on this experiment branch. Every transfer circuit moved to
// EdDSA-Poseidon spend authority, which adds private inputs, so the committed
// keys cannot prove current witnesses at all -- they are not merely drifted, they
// are unusable. Recording their old counts here would assert the opposite. The
// benchmark therefore generates its own setup instead of loading committed keys,
// and this map fills back in after the next key rotation.
var KeyPinned = map[string]Fingerprint{}

// KnownKeyDrift lists every proving key whose embedded constraint system differs
// from the current sources, and by how many constraints (key minus source).
// TestKnownKeyDriftIsComplete fails when a key drifts that is not listed here,
// so a new divergence cannot hide behind an existing one. Empty while KeyPinned
// is empty.
var KnownKeyDrift = map[string]int{}
