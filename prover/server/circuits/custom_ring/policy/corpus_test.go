package policy

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// Written by custom-rings/policy/tests/policy_hash_corpus.rs.
const corpusPath = "../../../../../custom-rings/policy/tests/fixtures/policy-hash-corpus.json"

type corpus struct {
	Version uint8        `json:"version"`
	Cases   []corpusCase `json:"cases"`
}

type corpusCase struct {
	Sources      []corpusSource `json:"sources"`
	Rules        []corpusRow    `json:"rules"`
	InlineAssets []string       `json:"inlineAssets"`
	InlineLimits []uint64       `json:"inlineLimits"`
	PolicyHash   string         `json:"policyHash"`
}

type corpusSource struct {
	ListId    int64  `json:"listId"`
	OwnerHash string `json:"ownerHash"`
}

type corpusRow struct {
	Subject   int64  `json:"subject"`
	Mode      int64  `json:"mode"`
	Mask      int64  `json:"mask"`
	AltMask   int64  `json:"altMask"`
	GuardTag  int64  `json:"guardTag"`
	Threshold uint64 `json:"threshold"`
}

func TestPolicyHashCorpus(t *testing.T) {
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if c.Version != PolicyVersion {
		t.Fatalf("corpus version %d, circuit PolicyVersion %d", c.Version, PolicyVersion)
	}
	if len(c.Cases) == 0 {
		t.Fatal("empty corpus")
	}
	for i, tc := range c.Cases {
		if len(tc.Sources) != NSources {
			t.Fatalf("case %d has %d source slots", i, len(tc.Sources))
		}
		var sources [NSources]source
		for j, s := range tc.Sources {
			sources[j] = source{listId: s.ListId, owner: hexField(t, s.OwnerHash)}
		}
		rules := make([]rule, len(tc.Rules))
		for j, r := range tc.Rules {
			rules[j] = rule{subject: r.Subject, mode: r.Mode, mask: r.Mask, altMask: r.AltMask, guardTag: r.GuardTag, threshold: r.Threshold}
		}
		assets := make([]*big.Int, len(tc.InlineAssets))
		for j, a := range tc.InlineAssets {
			assets[j] = hexField(t, a)
		}
		got := hex32(hostPolicyHash(t, rules, assets, tc.InlineLimits, sources))
		if got != tc.PolicyHash {
			t.Fatalf("case %d hashes to %s, the Rust side pins %s", i, got, tc.PolicyHash)
		}
	}
}

func hexField(t *testing.T, value string) *big.Int {
	t.Helper()
	bytes, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex %q: %v", value, err)
	}
	return new(big.Int).SetBytes(bytes)
}
