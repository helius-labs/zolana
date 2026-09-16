package policy

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"
)

// Written by custom-rings/policy/tests/policy_hash_corpus.rs.
const corpusPath = "../../../../../custom-rings/policy/tests/fixtures/policy-hash-corpus.json"

type corpus struct {
	Version uint8        `json:"version"`
	Cases   []corpusCase `json:"cases"`
}

type corpusCase struct {
	Sources      []corpusSource   `json:"sources"`
	Rules        []corpusRow      `json:"rules"`
	InlineAssets []string         `json:"inlineAssets"`
	InlineLimits []uint64         `json:"inlineLimits"`
	WindowSlots  uint64           `json:"windowSlots"`
	Velocity     []corpusVelocity `json:"velocity"`
	PolicyHash   string           `json:"policyHash"`
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

type corpusVelocity struct {
	Asset       string `json:"asset"`
	Cap         uint64 `json:"cap"`
	CosignAbove uint64 `json:"cosignAbove"`
}

type policyHashCorpusCircuit struct {
	Policy CustomRingPolicyCircuit
	Hash   frontend.Variable `gnark:",public"`
}

func (c *policyHashCorpusCircuit) Define(api frontend.API) error {
	checked := c.Policy.checkPolicy(api, rangecheck.New(api))
	api.AssertIsEqual(c.Hash, checked.hash)
	return nil
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
	statement := newStatement(t, defaultFixture())
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
		velocity := make([]velocityRow, len(tc.Velocity))
		for j, row := range tc.Velocity {
			velocity[j] = velocityRow{asset: hexField(t, row.Asset), cap: row.Cap, cosign: row.CosignAbove}
		}
		got := hex32(hostPolicy{
			rules:        rules,
			inlineAssets: assets,
			inlineLimits: tc.InlineLimits,
			sources:      sources,
			windowSlots:  tc.WindowSlots,
			velocity:     velocity,
		}.hash(t))
		if got != tc.PolicyHash {
			t.Fatalf("case %d hashes to %s, the Rust side pins %s", i, got, tc.PolicyHash)
		}
		statement.sources, statement.rules = sources, rules
		statement.inlineAssets, statement.inlineLimits = assets, tc.InlineLimits
		statement.windowSlots, statement.velocity = tc.WindowSlots, velocity
		assignment := &policyHashCorpusCircuit{
			Policy: *statement.assignment(t, nil),
			Hash:   hexField(t, tc.PolicyHash),
		}
		if err := test.IsSolved(&policyHashCorpusCircuit{}, assignment, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("case %d differs from the policy constraints: %v", i, err)
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
