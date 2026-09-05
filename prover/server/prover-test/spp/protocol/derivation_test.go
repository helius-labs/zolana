package protocol

import (
	"math/big"
	"testing"
)

func TestTransactionSecretDomainsAreAsciiTags(t *testing.T) {
	if OutputBlindingSeedDomainV1 != 0x54584f53 { // "TXOS"
		t.Fatalf("OutputBlindingSeedDomainV1 = %#x", OutputBlindingSeedDomainV1)
	}
	if PrivateTxBlindingDomainV1 != 0x54585042 { // "TXPB"
		t.Fatalf("PrivateTxBlindingDomainV1 = %#x", PrivateTxBlindingDomainV1)
	}
}

// TestTransactionSecretChildrenMatchPinnedVectors fixes the wire-level
// derivation. The Rust client must reproduce these exact values for
// first_nullifier = 7 and tx_secret = 42; a mismatch means client and circuit
// disagree on private_tx_hash or on every output blinding.
func TestTransactionSecretChildrenMatchPinnedVectors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		derive func(firstNullifier, txSecret *big.Int) (*big.Int, error)
		want   string
	}{
		{
			"output_blinding_seed",
			OutputBlindingSeed,
			"06bca316066630056539772e0d19f5d9453331f9dda2f0d08ee0632b6b512de3",
		},
		{
			"private_tx_blinding",
			PrivateTxBlinding,
			"1991f166208c440ba5ecdb0f8ccc792e8d2739038ae9d99862621cf2c292f610",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, ok := new(big.Int).SetString(tc.want, 16)
			if !ok {
				t.Fatalf("parse expected %s", tc.name)
			}
			got, err := tc.derive(fe(7), fe(42))
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			if got.Cmp(want) != 0 {
				t.Fatalf("%s = %064x, want %064x", tc.name, got, want)
			}
		})
	}
}

// TestTransactionSecretChildrenDiffer is what the domain separation buys: one
// secret and one first nullifier produce two unrelated children, so a party
// holding one cannot reach the other.
func TestTransactionSecretChildrenDiffer(t *testing.T) {
	seed, err := OutputBlindingSeed(fe(7), fe(42))
	if err != nil {
		t.Fatalf("output blinding seed: %v", err)
	}
	blinding, err := PrivateTxBlinding(fe(7), fe(42))
	if err != nil {
		t.Fatalf("private tx blinding: %v", err)
	}
	if seed.Cmp(blinding) == 0 {
		t.Fatal("the two children of one transaction secret collided")
	}
}

// TestTransactionSecretChildrenBindFirstNullifier is the uniqueness property:
// a nullifier enters the nullifier tree once, so reusing a transaction secret
// across two accepted transactions still yields different children.
func TestTransactionSecretChildrenBindFirstNullifier(t *testing.T) {
	for _, tc := range []struct {
		name   string
		derive func(firstNullifier, txSecret *big.Int) (*big.Int, error)
	}{
		{"output_blinding_seed", OutputBlindingSeed},
		{"private_tx_blinding", PrivateTxBlinding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, err := tc.derive(fe(7), fe(42))
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			second, err := tc.derive(fe(8), fe(42))
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			if first.Cmp(second) == 0 {
				t.Fatal("child did not change with the first nullifier")
			}
			repeat, err := tc.derive(fe(7), fe(42))
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			if first.Cmp(repeat) != 0 {
				t.Fatal("derivation is not deterministic")
			}
		})
	}
}

func TestTransactionSecretChildrenRejectInvalidFieldElements(t *testing.T) {
	if _, err := OutputBlindingSeed(nil, fe(42)); err == nil {
		t.Fatal("expected a nil first nullifier to fail")
	}
	if _, err := PrivateTxBlinding(fe(7), nil); err == nil {
		t.Fatal("expected a nil transaction secret to fail")
	}
}
