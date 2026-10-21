package policy_test

import (
	"encoding/json"
	"math/big"
	"os"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/policy"
	"github.com/helius-labs/zolana/prover/server/prover-test/refusal"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringpolicy"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringrecords"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

const (
	policyTableVectors = "../../../../../test-vectors/ring-policy-table.json"
	policyRuleVectors  = "../../../../../test-vectors/ring-policy-rules.json"
	statementVectors   = "../../../../../test-vectors/ring-statements.json"
)

// tableRows are the table parts both policy vector files carry.
type tableRows struct {
	Sources []struct {
		ListID   int64           `json:"list_id"`
		Registry ringrecords.Hex `json:"registry"`
	} `json:"sources"`
	Rules        []ringrecords.Hex `json:"rules"`
	InlineAssets []ringrecords.Hex `json:"inline_assets"`
	InlineLimits []uint64          `json:"inline_limits"`
	Limits       []struct {
		Asset       ringrecords.Hex `json:"asset"`
		Cap         uint64          `json:"cap"`
		CosignAbove uint64          `json:"cosign_above"`
	} `json:"limits"`
}

// tableVector is one case custom-rings/policy/tests/policy_table_vector.rs writes.
type tableVector struct {
	Name string `json:"name"`
	tableRows
	RuleParts  []ruleParts       `json:"rule_parts"`
	Fields     []ringrecords.Hex `json:"fields"`
	PolicyHash ringrecords.Hex   `json:"policy_hash"`
}

// ruleVector is one case custom-rings/policy/tests/policy_rules_vector.rs writes.
type ruleVector struct {
	Name string `json:"name"`
	tableRows
	OwnRecords     []recordVector  `json:"own_records"`
	CuratorRecords []recordVector  `json:"curator_records"`
	Sender         ringrecords.Hex `json:"sender"`
	Outputs        []struct {
		Owner  ringrecords.Hex `json:"owner"`
		Asset  ringrecords.Hex `json:"asset"`
		Amount uint64          `json:"amount"`
	} `json:"outputs"`
	Outcome struct {
		Kind string `json:"kind"`
		Rule int    `json:"rule"`
	} `json:"outcome"`
}

type recordVector struct {
	Member ringrecords.Hex `json:"member"`
	Lists  uint64          `json:"lists"`
}

// ruleParts is one row split from its low byte, the enumerated parts by their Rust names.
type ruleParts struct {
	Subject     string `json:"subject"`
	Mode        string `json:"mode"`
	Mask        uint8  `json:"mask"`
	Guard       string `json:"guard"`
	Threshold   uint64 `json:"threshold"`
	Alternative uint8  `json:"alternative"`
}

var (
	subjects = map[string]uint64{"output_owner": policy.SubjectOutputOwner, "sender": policy.SubjectSender, "asset": policy.SubjectAsset}
	modes    = map[string]uint64{"present": policy.ModePresent, "absent": policy.ModeAbsent}
	guards   = map[string]uint64{"always": policy.GuardAlways, "above_amount": policy.GuardAboveAmount, "above_amount_by_asset": policy.GuardAboveAmountByAsset}
)

type tableCircuit struct {
	Table      policy.Table
	PolicyHash frontend.Variable
}

func (c *tableCircuit) Define(api frontend.API) error {
	policy.DecodeTable(c.Table, api, rangecheck.New(api), c.PolicyHash)
	return nil
}

func TestPolicyTableMatchesRustVectors(t *testing.T) {
	raw, err := os.ReadFile(policyTableVectors)
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Version int           `json:"version"`
		Cases   []tableVector `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Version != policy.PolicyTableVersion || len(vectors.Cases) == 0 {
		t.Fatalf("version %d with %d cases, want version %d", vectors.Version, len(vectors.Cases), policy.PolicyTableVersion)
	}
	for _, v := range vectors.Cases {
		t.Run(v.Name, func(t *testing.T) {
			if len(v.RuleParts) != len(v.Rules) {
				t.Fatalf("%d rule parts for %d rules", len(v.RuleParts), len(v.Rules))
			}
			for i, parts := range v.RuleParts {
				want := parts.values(t)
				got := make([]*big.Int, len(want))
				for k := range got {
					got[k] = new(big.Int)
				}
				if err := policy.RulePartsHint(ecc.BN254.ScalarField(), []*big.Int{v.Rules[i].Int}, got); err != nil {
					t.Fatal(err)
				}
				for k := range want {
					if !got[k].IsUint64() || got[k].Uint64() != want[k] {
						t.Fatalf("rule %d part %d is %v, its vector part reads %d", i, k, got[k], want[k])
					}
				}
			}
			table := v.rows().Wires()
			fields := spptest.ToBigInts(table.Fields())
			if len(fields) != len(v.Fields) {
				t.Fatalf("%d fields, the vector has %d", len(fields), len(v.Fields))
			}
			for i, want := range v.Fields {
				if fields[i].Cmp(want.Int) != 0 {
					t.Fatalf("field %d is %x, the vector has %x", i, fields[i], want.Int)
				}
			}
			hash := v.PolicyHash.Int
			if host := ringpolicy.TableHash(t, table); host.Cmp(hash) != 0 {
				t.Fatalf("host hash %x, the vector has %x", host, hash)
			}
			if err := test.IsSolved(&tableCircuit{}, &tableCircuit{Table: table, PolicyHash: hash}, ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
			other := new(big.Int).Add(hash, big.NewInt(1))
			if test.IsSolved(&tableCircuit{}, &tableCircuit{Table: table, PolicyHash: other}, ecc.BN254.ScalarField()) == nil {
				t.Fatal("a table opened under another policy_hash")
			}
		})
	}
}

// A refused transfer breaks the rule its vector names, the rules before that one admit it.
func TestPolicyRulesMatchRustVectors(t *testing.T) {
	raw, err := os.ReadFile(policyRuleVectors)
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []ruleVector `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("no policy rule vectors")
	}
	for _, v := range vectors.Cases {
		t.Run(v.Name, func(t *testing.T) {
			switch v.Outcome.Kind {
			case "pass":
				if err := v.solve(t, len(v.Rules)); err != nil {
					t.Fatalf("an admitted transfer is refused: %v", err)
				}
			case "lists", "no_asset_limit", "mixed_assets":
				if err := v.solve(t, v.Outcome.Rule); err != nil {
					t.Fatalf("the rules before rule %d refuse: %v", v.Outcome.Rule, err)
				}
				for _, rules := range []int{v.Outcome.Rule + 1, len(v.Rules)} {
					refusal.Require(t, v.solve(t, rules), "policy.(*Policy).assertRules")
				}
			default:
				t.Fatalf("outcome %q", v.Outcome.Kind)
			}
		})
	}
}

// statementVector is one policy statement custom-rings/interface/tests/vectors.rs writes, anonymous is null on the delegate key.
type statementVector struct {
	Key              string            `json:"key"`
	Anonymous        *bool             `json:"anonymous"`
	PrivateTxHash    ringrecords.Hex   `json:"private_tx_hash"`
	PolicyHash       ringrecords.Hex   `json:"policy_hash"`
	RingID           ringrecords.Hex   `json:"ring_id"`
	ApprovalRequired bool              `json:"approval_required"`
	KeyEscrow        bool              `json:"key_escrow"`
	OwnRoot          ringrecords.Hex   `json:"own_root"`
	CuratorRoot      ringrecords.Hex   `json:"curator_root"`
	Sender           ringrecords.Hex   `json:"sender"`
	PublicAssets     []ringrecords.Hex `json:"public_assets"`
	PublicAmounts    []ringrecords.Hex `json:"public_amounts"`
	PublicInputHash  ringrecords.Hex   `json:"public_input_hash"`
}

type memberStatementCircuit struct{ policy.MemberPolicyCircuit }

func (c *memberStatementCircuit) Define(api frontend.API) error {
	policy.BindMemberStatement(api, &c.MemberPolicyCircuit)
	return nil
}

type delegateStatementCircuit struct{ policy.DelegatePolicyCircuit }

func (c *delegateStatementCircuit) Define(api frontend.API) error {
	policy.BindDelegateStatement(api, &c.DelegatePolicyCircuit)
	return nil
}

func TestPolicyStatementsMatchRustVectors(t *testing.T) {
	raw, err := os.ReadFile(statementVectors)
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Policy []statementVector `json:"policy"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Policy) == 0 {
		t.Fatal("no policy statement vectors")
	}
	for _, v := range vectors.Policy {
		name := v.Key
		if v.Anonymous != nil && *v.Anonymous {
			name += "_anonymous"
		}
		t.Run(name, func(t *testing.T) {
			hash := v.PublicInputHash.Int
			for _, publicInputHash := range []*big.Int{hash, new(big.Int).Add(hash, big.NewInt(1))} {
				circuit, assignment := v.circuits(t, publicInputHash)
				err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
				if (err == nil) != (publicInputHash == hash) {
					t.Fatalf("public input %x, vector %x, solve %v", publicInputHash, hash, err)
				}
			}
		})
	}
}

// circuits binds the vector's statement values to publicInputHash, every other wire keeps an honest world's value.
func (v statementVector) circuits(t *testing.T, publicInputHash *big.Int) (frontend.Circuit, frontend.Circuit) {
	t.Helper()
	member := v.Key == "member" && v.Anonymous != nil
	delegated := v.Key == "delegate" && v.Anonymous == nil && !v.ApprovalRequired && v.KeyEscrow && v.Sender.Sign() == 0
	if !member && !delegated {
		t.Fatalf("key %q with anonymous %v, approval %v, key escrow %v fits no key", v.Key, v.Anonymous, v.ApprovalRequired, v.KeyEscrow)
	}
	w := ringpolicy.Delegate(shared.Shape{NInputs: 2, NOutputs: 2})
	if member {
		w = ringpolicy.Confidential()
		w.Anonymous, w.ApprovalRequired, w.KeyEscrow = *v.Anonymous, v.ApprovalRequired, v.KeyEscrow
	}
	b := w.Build(t)
	p := b.Policy()
	p.PrivateTxHash, p.PolicyHash, p.RingID = v.PrivateTxHash.Int, v.PolicyHash.Int, v.RingID.Int
	p.OwnRoot, p.CuratorRoot = v.OwnRoot.Int, v.CuratorRoot.Int
	for k := range p.PublicAssets {
		p.PublicAssets[k], p.PublicAmounts[k] = v.PublicAssets[k].Int, v.PublicAmounts[k].Int
	}
	if member {
		b.Member.Sender = v.Sender.Int
	}
	b.Rebind(t)
	if delegated {
		v.requireHostStatement(t, b.Delegate.PublicInputHash)
		b.Delegate.PublicInputHash = publicInputHash
		skeleton, err := policy.NewDelegatePolicyCircuit(w.Shape)
		if err != nil {
			t.Fatal(err)
		}
		return &delegateStatementCircuit{*skeleton}, &delegateStatementCircuit{*b.Delegate}
	}
	v.requireHostStatement(t, b.Member.PublicInputHash)
	b.Member.PublicInputHash = publicInputHash
	skeleton, err := policy.NewMemberPolicyCircuit(w.Outputs)
	if err != nil {
		t.Fatal(err)
	}
	return &memberStatementCircuit{*skeleton}, &memberStatementCircuit{*b.Member}
}

func (v statementVector) requireHostStatement(t *testing.T, host frontend.Variable) {
	t.Helper()
	if got := spptest.AsBigInt(host); got.Cmp(v.PublicInputHash.Int) != 0 {
		t.Fatalf("host statement %x, the vector has %x", got, v.PublicInputHash.Int)
	}
}

// values lists the parts in the circuit's split order, each enumerated name read through its Go constant.
func (r ruleParts) values(t *testing.T) []uint64 {
	t.Helper()
	named := func(names map[string]uint64, name string) uint64 {
		value, ok := names[name]
		if !ok {
			t.Fatalf("no Go constant for %q", name)
		}
		return value
	}
	return []uint64{named(subjects, r.Subject), named(modes, r.Mode), uint64(r.Mask), named(guards, r.Guard), r.Threshold, uint64(r.Alternative)}
}

func (v tableRows) rows() ringpolicy.Rows {
	var rows ringpolicy.Rows
	for _, source := range v.Sources {
		rows.Sources = append(rows.Sources, policy.SourceWires{ListID: source.ListID, Registry: source.Registry.Int})
	}
	for _, rule := range v.Rules {
		rows.Rules = append(rows.Rules, rule.Int)
	}
	for i, asset := range v.InlineAssets {
		rows.InlineAssets, rows.InlineLimits = append(rows.InlineAssets, asset.Int), append(rows.InlineLimits, v.InlineLimits[i])
	}
	for _, limit := range v.Limits {
		rows.Limits = append(rows.Limits, policy.OutflowLimitWires{Asset: limit.Asset.Int, Cap: limit.Cap, CosignAbove: limit.CosignAbove})
	}
	return rows
}

// solve runs the smallest member key holding the outputs under the table's first rules.
func (v ruleVector) solve(t *testing.T, rules int) error {
	t.Helper()
	capacity := slices.IndexFunc(policy.MemberOutputs[:], func(outputs int) bool { return outputs >= len(v.Outputs) })
	if capacity < 0 {
		t.Fatalf("%d outputs exceed every member key", len(v.Outputs))
	}
	w := ringpolicy.World{
		Outputs: policy.MemberOutputs[capacity],
		Sender:  memberID(t, v.Sender),
		Own:     records(t, v.OwnRecords),
		Curator: records(t, v.CuratorRecords),
	}
	for _, out := range v.Outputs {
		owner := memberID(t, out.Owner)
		w.Slots = append(w.Slots, ringpolicy.Slot{Owner: owner, Asset: memberID(t, out.Asset), Amount: out.Amount, Unowned: owner == 0})
	}
	rows := v.rows()
	rows.Rules = rows.Rules[:rules]
	b := w.BuildRows(t, rows)
	return test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField())
}

func records(t *testing.T, vectors []recordVector) map[int64]ringpolicy.Record {
	t.Helper()
	out := make(map[int64]ringpolicy.Record, len(vectors))
	for _, r := range vectors {
		out[memberID(t, r.Member)] = ringpolicy.Record{Lists: r.Lists}
	}
	return out
}

// memberID reads a vector member as the int64 a world keys its members by.
func memberID(t *testing.T, member ringrecords.Hex) int64 {
	t.Helper()
	if !member.IsInt64() {
		t.Fatalf("member %x exceeds int64", member.Int)
	}
	return member.Int64()
}
