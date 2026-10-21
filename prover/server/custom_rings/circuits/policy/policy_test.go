package policy_test

import (
	"fmt"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/policy"
	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
	"github.com/helius-labs/zolana/prover/server/prover-test/refusal"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringpolicy"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringrecords"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
)

// pins holds every key's count, compiled with the ring prover's option (prover/custom_ring/ring.go).
var pins = map[string]int{
	"member_2": 48455, "member_4": 82348, "member_8": 150253, "member_16": 286047,
	"delegate_1x2": 48736, "delegate_1x4": 82565, "delegate_1x8": 150391, "delegate_1x16": 285928,
	"delegate_2x2": 50089, "delegate_2x4": 83918, "delegate_2x8": 151744, "delegate_2x16": 287281,
	"delegate_3x2": 51442, "delegate_3x4": 85271, "delegate_3x8": 153097,
	"delegate_4x2": 52795, "delegate_4x4": 86624, "delegate_4x8": 154450, "delegate_4x16": 289987,
	"delegate_5x2": 54148, "delegate_5x4": 87977, "delegate_5x8": 155803, "delegate_5x16": 291340,
	"delegate_6x2": 55501, "delegate_6x4": 89330, "delegate_6x8": 157156,
	"delegate_8x2": 58207, "delegate_8x4": 92036, "delegate_8x8": 159862, "delegate_8x16": 295399,
	"delegate_12x2": 63619, "delegate_12x4": 97448, "delegate_12x8": 165274,
	"delegate_16x2": 69031, "delegate_16x4": 102860, "delegate_16x8": 170686,
	"delegate_24x2": 79855, "delegate_24x4": 113684,
	"delegate_32x2": 90679, "delegate_40x2": 101503,
}

// targets cap the keys held to a constraint budget, transaction bytes bound the rest.
var targets = map[string]int{"member_2": 100_000, "member_4": 100_000, "delegate_2x2": 150_000, "delegate_4x4": 150_000}

type policyKey struct {
	name    string
	circuit func() (frontend.Circuit, error)
	honest  func() ringpolicy.World
}

func TestPolicyKeys(t *testing.T) {
	keys := policyKeys()
	if len(keys) != len(pins) {
		t.Fatalf("%d keys, %d pins", len(keys), len(pins))
	}
	for _, key := range keys {
		t.Run(key.name, func(t *testing.T) {
			cs := compiled(t, key.name, key.circuit)
			pin, pinned := pins[key.name]
			target, bounded := targets[key.name]
			if got := cs.GetNbConstraints(); !pinned || got != pin || bounded && got >= target {
				t.Fatalf("%d constraints, pinned %d below %d", got, pin, target)
			}
			// groth16-solana verifies one BSB22 commitment over private wires only.
			commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
			if !ok || len(commitments) != 1 || commitments[0].NbPublicCommitted != 0 {
				t.Fatalf("commitments %+v, want one over private wires", cs.GetCommitments())
			}
			requireCompiledSolved(t, cs, key.honest().Build(t))
		})
	}
	t.Run("anonymous", func(t *testing.T) {
		requireCompiledSolved(t, compiled(t, "member_2", member(2)), ringpolicy.Anonymous().Build(t))
	})
	t.Run("curator", func(t *testing.T) {
		requireCompiledSolved(t, compiled(t, "member_2", member(2)), curated().Build(t))
	})
	for _, outputs := range policy.MemberOutputs {
		name := fmt.Sprintf("member_%d", outputs)
		t.Run(name+" u64 extremes", func(t *testing.T) {
			requireCompiledSolved(t, compiled(t, name, member(outputs)), extremes(t, outputs))
		})
	}
	for _, r := range refusals {
		capacities := []int{0}
		if r.wide {
			capacities = append(capacities, 8, 16)
		}
		for _, outputs := range capacities {
			name := r.name
			if outputs != 0 {
				name = fmt.Sprintf("%s on the %d-output key", r.name, outputs)
			}
			honest := func() ringpolicy.World {
				w := r.honest()
				if outputs != 0 {
					w.Outputs = outputs
				}
				return w
			}
			t.Run(name, func(t *testing.T) {
				requireSolved(t, honest().Build(t))
				w := honest()
				if r.world != nil {
					r.world(&w)
				}
				b := w.Build(t)
				if r.witness != nil {
					r.witness(t, b)
				}
				refusal.Require(t, test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()), r.in)
			})
		}
	}
	for _, f := range forgeries {
		t.Run(f.name, func(t *testing.T) {
			requireForgeryRefused(t, f.hint, f.forge)
		})
	}
}

// forgeries each rewrite outputs of one hint on the honest 2-output member witness, exactly one constraint binding it breaks.
var forgeries = []struct {
	name  string
	hint  solver.Hint
	forge func(q *big.Int, in, out []*big.Int)
}{
	{name: "comparison bit flipped", hint: policy.ComparisonHint, forge: func(_ *big.Int, _, out []*big.Int) {
		if out[1].Sign() == 0 {
			out[1].SetInt64(1)
		}
	}},
	{name: "comparison low part wrapped", hint: policy.ComparisonHint, forge: func(_ *big.Int, in, out []*big.Int) {
		if out[1].Sign() == 0 {
			out[0].Sub(out[0], new(big.Int).Lsh(big.NewInt(1), uint(in[1].Uint64())))
			out[1].SetInt64(1)
		}
	}},
	{name: "comparison bit off the bits", hint: policy.ComparisonHint, forge: func(q *big.Int, in, out []*big.Int) {
		if out[1].Sign() == 0 {
			step := new(big.Int).ModInverse(new(big.Int).Lsh(big.NewInt(1), uint(in[1].Uint64())), q)
			out[0].Add(out[0], big.NewInt(1))
			out[1].Sub(out[1], step).Mod(out[1], q)
		}
	}},
	{name: "rule part carried into its neighbour", hint: policy.RulePartsHint, forge: func(_ *big.Int, _, out []*big.Int) {
		out[0].Add(out[0], big.NewInt(1<<8))
		out[1].Sub(out[1], big.NewInt(1))
	}},
	{name: "rule subject dropped", hint: policy.RulePartsHint, forge: func(_ *big.Int, _, out []*big.Int) {
		out[0].SetInt64(0)
	}},
}

// refusals each mutate one honest value, the circuit refuses inside the named function, a wide one also on the 8- and 16-output keys.
var refusals = []struct {
	name    string
	honest  func() ringpolicy.World
	world   func(*ringpolicy.World)
	witness func(testing.TB, ringpolicy.Witness)
	in      string
	wide    bool
}{
	{name: "owner record claiming a list it lacks", honest: ringpolicy.Confidential, witness: func(_ testing.TB, b ringpolicy.Witness) {
		b.Policy().OwnerEntries[0].Own.Lists = ringrecords.AllowBit | ringrecords.BlockBit
	}, in: "records.QuadOpening.Resolve", wide: true},
	{name: "public deposit above the outflow to others", honest: deposited, world: func(w *ringpolicy.World) { w.Public[0].Amount = 400 }, in: "policy.(*Policy).constrainOutflow", wide: true},
	{name: "dummy amount covering a public deposit", honest: dummyDeposit, world: func(w *ringpolicy.World) { w.Public[0].Amount = 150 }, in: "policy.(*Policy).constrainOutflow"},
	{name: "withdrawal past the cap", honest: withdrawn, world: func(w *ringpolicy.World) { w.Public[0].Amount = -800 }, in: "policy.(*Policy).constrainOutflow", wide: true},
	{name: "approval bit 0 past the co-sign bound", honest: cosigned, world: func(w *ringpolicy.World) { w.ApprovalRequired = false }, in: "policy.(*MemberPolicyCircuit).assertApproval", wide: true},
	{name: "approval bit 1 within every co-sign bound", honest: ringpolicy.Four, world: func(w *ringpolicy.World) { w.ApprovalRequired = true }, in: "policy.(*MemberPolicyCircuit).assertApproval"},
	{name: "approval bit 1 under a cap without a co-sign bound", honest: capOnly, world: func(w *ringpolicy.World) { w.ApprovalRequired = true }, in: "policy.(*MemberPolicyCircuit).assertApproval"},
	{name: "exit to the sender counted as outflow", honest: exited, world: func(w *ringpolicy.World) { w.Slots[1].Amount = 201 }, in: "policy.(*MemberPolicyCircuit).assertApproval"},
	{name: "anonymous sender that is not the commitment", honest: ringpolicy.Anonymous, witness: func(t testing.TB, b ringpolicy.Witness) {
		b.Member.Sender = ringpolicy.Sender
		b.Rebind(t)
	}, in: "policy.(*MemberPolicyCircuit).sender", wide: true},
	{name: "delegate move with a second member's input", honest: delegate2, world: func(w *ringpolicy.World) {
		w.Inputs[1] = ringpolicy.Slot{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 100}
	}, in: "policy.(*DelegatePolicyCircuit).sender"},
	{name: "delegate move without a spent input", honest: delegate2, world: func(w *ringpolicy.World) { w.Inputs[0] = ringpolicy.Slot{} }, in: "policy.(*DelegatePolicyCircuit).sender"},
	{name: "owner off a required list", honest: ringpolicy.Confidential, world: func(w *ringpolicy.World) { w.Own[ringpolicy.Alice] = ringpolicy.Escrowed(0) }, in: "policy.(*Policy).assertRules", wide: true},
	{name: "owner on a forbidden list", honest: blocked, world: func(w *ringpolicy.World) {
		w.Own[ringpolicy.Alice] = ringpolicy.Escrowed(ringrecords.AllowBit | ringrecords.BlockBit)
	}, in: "policy.(*Policy).assertRules", wide: true},
	{name: "sender on a forbidden list", honest: ringpolicy.Confidential, world: func(w *ringpolicy.World) {
		w.Own[ringpolicy.Sender] = ringpolicy.Escrowed(ringrecords.AllowBit | ringrecords.FrozenBit)
	}, in: "policy.(*Policy).assertRules", wide: true},
	{name: "asset off a required list", honest: ringpolicy.Four, world: func(w *ringpolicy.World) { delete(w.Own, ringpolicy.AssetB) }, in: "policy.(*Policy).assertRules", wide: true},
	{name: "curator list missing from the curator registry", honest: curated, world: func(w *ringpolicy.World) { delete(w.Curator, ringpolicy.Alice) }, in: "policy.(*Policy).assertRules", wide: true},
	{name: "subject on an alternative list", honest: alternative, world: func(w *ringpolicy.World) { w.Own[ringpolicy.Alice] = ringpolicy.Escrowed(ringrecords.BlockBit) }, in: "policy.(*Policy).assertRules", wide: true},
	{name: "scalar guard above its threshold", honest: scalarGuarded, world: func(w *ringpolicy.World) { w.Slots[0].Amount = 600 }, in: "policy.(*Policy).assertRules", wide: true},
	{name: "scalar guard over two assets", honest: scalarGuarded, world: func(w *ringpolicy.World) { w.Slots[1].Asset = ringpolicy.AssetB }, in: "policy.(*Policy).assertRules"},
	{name: "asset guard above the inline limit", honest: assetGuarded, world: func(w *ringpolicy.World) { w.Slots[0].Amount = 600 }, in: "policy.(*Policy).assertRules", wide: true},
	{name: "asset guard without an inline limit", honest: assetGuardedListed, world: func(w *ringpolicy.World) { w.Slots[0].Asset = ringpolicy.AssetB }, in: "policy.(*Policy).assertRules"},
	{name: "scalar guard over split outputs", honest: scalarSplit, world: func(w *ringpolicy.World) { w.Slots[1].Amount = 300 }, in: "policy.(*Policy).assertRules"},
	{name: "asset scalar guard above its threshold", honest: assetScalarGuarded, world: func(w *ringpolicy.World) { w.Slots[1].Amount = 300 }, in: "policy.(*Policy).assertRules"},
	{name: "escrow of another key ciphertext", honest: ringpolicy.Confidential, witness: func(_ testing.TB, b ringpolicy.Witness) { b.Policy().Outputs[0].CtHash = 7 }, in: "policy.(*Policy).assertEscrow"},
	{name: "escrow without a registered key", honest: ringpolicy.Confidential, world: func(w *ringpolicy.World) {
		w.Own[ringpolicy.Alice] = ringpolicy.Record{Lists: ringrecords.AllowBit}
	}, in: "policy.(*Policy).assertEscrow", wide: true},
	{name: "delegate output owner without a registered key", honest: delegate2, world: func(w *ringpolicy.World) {
		w.Own[ringpolicy.Alice] = ringpolicy.Record{Lists: ringrecords.AllowBit}
	}, in: "policy.(*Policy).assertEscrow"},
	{name: "table row the program never hashed", honest: ringpolicy.Confidential, witness: func(_ testing.TB, b ringpolicy.Witness) {
		b.Policy().Rules[1] = ringpolicy.Require(policy.SubjectSender, ringrecords.FrozenBit).Packed()
	}, in: "policy.Table.decode"},
	{name: "output SPP never settled", honest: ringpolicy.Confidential, witness: func(_ testing.TB, b ringpolicy.Witness) { b.Policy().Outputs[0].Amount = 301 }, in: "policy.(*Policy).openOutputs", wide: true},
	{name: "opening under another root", honest: ringpolicy.Confidential, witness: func(t testing.TB, b ringpolicy.Witness) {
		b.Policy().OwnRoot = 5
		b.Rebind(t)
	}, in: "records.QuadOpening.Resolve"},
	{name: "curator root outside the statement", honest: ringpolicy.Confidential, witness: func(_ testing.TB, b ringpolicy.Witness) { b.Policy().CuratorRoot = 5 }, in: "policy.bindStatement"},
}

func curated() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Table.Curator = map[uint64]bool{ringrecords.AllowBit: true}
	for _, m := range []int64{ringpolicy.Sender, ringpolicy.Alice} {
		w.Own[m] = ringpolicy.Escrowed(0)
		w.Curator[m] = ringpolicy.Record{Lists: ringrecords.AllowBit}
	}
	return w
}

func deposited() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: 100}}
	return w
}

// withdrawn moves an outflow of 800 past the co-sign bound, within the cap, beside a deposit of another asset.
func withdrawn() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: -500}, {Asset: ringpolicy.AssetB, Amount: 1000}}
	w.ApprovalRequired = true
	return w
}

// extremes pays alice the u64 maximum on every output beside a u64 maximum withdrawal, the widest differences the key compares.
func extremes(t testing.TB, outputs int) ringpolicy.Witness {
	w := ringpolicy.Four()
	w.Outputs = outputs
	w.Table.Rules[0].Guard, w.Table.Rules[0].Threshold = policy.GuardAboveAmount, 500
	w.Table.Limits = []ringpolicy.OutflowLimit{{Asset: ringpolicy.AssetA, CosignAbove: 1}}
	w.Slots = nil
	for range outputs {
		w.Slots = append(w.Slots, ringpolicy.Slot{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: math.MaxUint64})
	}
	w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: -1}}
	w.ApprovalRequired = true
	b := w.Build(t)
	// A world's int64 public amounts stop short of a u64 maximum withdrawal.
	b.Policy().PublicAmounts[0] = protocol.SignedToField(new(big.Int).Neg(new(big.Int).SetUint64(math.MaxUint64)))
	b.Rebind(t)
	return b
}

func capOnly() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Table.Limits = []ringpolicy.OutflowLimit{{Asset: ringpolicy.AssetA, Cap: 1000}}
	return w
}

func dummyDeposit() ringpolicy.World {
	w := ringpolicy.Four()
	w.Slots = append(w.Slots, ringpolicy.Slot{Asset: ringpolicy.AssetA, Amount: 50})
	w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: 100}}
	return w
}

func cosigned() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Slots[0].Amount = 600
	w.ApprovalRequired = true
	return w
}

// exited sends the change out of the ring, an outflow of 500 at the co-sign bound.
func exited() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Slots[1].Exit = true
	return w
}

func blocked() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Table.Rules = append(w.Table.Rules, ringpolicy.Forbid(policy.SubjectOutputOwner, ringrecords.BlockBit))
	return w
}

func alternative() ringpolicy.World {
	w := ringpolicy.Confidential()
	rule := ringpolicy.Require(policy.SubjectOutputOwner, ringrecords.AllowBit)
	rule.Alternative = ringrecords.BlockBit
	w.Table.Rules[0] = rule
	w.Own[ringpolicy.Alice] = ringpolicy.Escrowed(0)
	return w
}

func scalarGuarded() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Table.Rules[0].Guard, w.Table.Rules[0].Threshold = policy.GuardAboveAmount, 500
	w.Own[ringpolicy.Alice] = ringpolicy.Escrowed(0)
	return w
}

func assetGuarded() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Table.Rules[0].Guard = policy.GuardAboveAmountByAsset
	w.Table.Inline = []ringpolicy.InlineLimit{{Asset: ringpolicy.AssetA, Limit: 500}}
	w.Own[ringpolicy.Alice] = ringpolicy.Escrowed(0)
	return w
}

func assetGuardedListed() ringpolicy.World {
	w := assetGuarded()
	w.Own[ringpolicy.Alice] = ringpolicy.Escrowed(ringrecords.AllowBit)
	return w
}

func scalarSplit() ringpolicy.World {
	w := scalarGuarded()
	w.Table.Limits = nil
	w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 300}, {Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 100}}
	return w
}

func assetScalarGuarded() ringpolicy.World {
	w := ringpolicy.Confidential()
	rule := ringpolicy.Require(policy.SubjectAsset, ringrecords.AllowBit)
	rule.Guard, rule.Threshold = policy.GuardAboveAmount, 500
	w.Table.Rules = append(w.Table.Rules, rule)
	w.Table.Limits = nil
	w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 300}, {Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 100}}
	return w
}

func delegate2() ringpolicy.World { return ringpolicy.Delegate(shared.Shape{NInputs: 2, NOutputs: 2}) }

// policyKeys lists every key prover/common/ring_keys.go generates, with the honest world it solves.
func policyKeys() []policyKey {
	var keys []policyKey
	for _, outputs := range policy.MemberOutputs {
		keys = append(keys, policyKey{name: fmt.Sprintf("member_%d", outputs), circuit: member(outputs), honest: ringpolicy.MemberWorlds[outputs]})
	}
	for _, ringAuthority := range protocol.RingAuthorityShapes {
		shape := shared.Shape(ringAuthority)
		keys = append(keys, policyKey{
			name:    fmt.Sprintf("delegate_%dx%d", shape.NInputs, shape.NOutputs),
			circuit: delegate(shape),
			honest:  func() ringpolicy.World { return ringpolicy.Delegate(shape) },
		})
	}
	return keys
}

func member(outputs int) func() (frontend.Circuit, error) {
	return func() (frontend.Circuit, error) { return policy.NewMemberPolicyCircuit(outputs) }
}

func delegate(shape shared.Shape) func() (frontend.Circuit, error) {
	return func() (frontend.Circuit, error) { return policy.NewDelegatePolicyCircuit(shape) }
}

func requireCompiledSolved(t *testing.T, cs constraint.ConstraintSystem, b ringpolicy.Witness) {
	t.Helper()
	witness, err := frontend.NewWitness(b.Assignment(), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(witness); err != nil {
		t.Fatal(err)
	}
}

func requireSolved(t *testing.T, b ringpolicy.Witness) {
	t.Helper()
	if err := test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

var compiledKeys sync.Map

func compiled(t *testing.T, name string, circuit func() (frontend.Circuit, error)) constraint.ConstraintSystem {
	t.Helper()
	if cs, ok := compiledKeys.Load(name); ok {
		return cs.(constraint.ConstraintSystem)
	}
	c, err := circuit()
	if err != nil {
		t.Fatal(err)
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	compiledKeys.Store(name, cs)
	return cs
}

// requireForgeryRefused solves the honest 2-output member witness with every call of hint forged, a constraint must refuse it.
func requireForgeryRefused(t *testing.T, hint solver.Hint, forge func(q *big.Int, in, out []*big.Int)) {
	cs := compiled(t, "member_2", member(2))
	witness, err := frontend.NewWitness(ringpolicy.Confidential().Build(t).Assignment(), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	var forged atomic.Bool
	err = cs.IsSolved(witness, solver.OverrideHint(solver.GetHintID(hint), func(q *big.Int, in, out []*big.Int) error {
		if err := hint(q, in, out); err != nil {
			return err
		}
		forge(q, in, out)
		forged.Store(true)
		return nil
	}), hintattack.SkipMissingLookupQueries(t))
	if !forged.Load() {
		t.Fatal("the forgery never ran")
	}
	hintattack.RequireConstraintRejection(t, err)
}
