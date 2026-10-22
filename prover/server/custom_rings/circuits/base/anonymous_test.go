package base_test

import (
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func compileAnonymous(t *testing.T, shape base.AnonymousAuditShape) *compiledAudit {
	t.Helper()
	circuit, err := base.NewAnonymousAuditCircuit(shape)
	if err != nil {
		t.Fatal(err)
	}
	return compileAudit(t, anonymousKeyName(t, shape), circuit, ringaudit.NewAnonymousAudit(t, shape).Circuit(t))
}

// entryShape is the cheapest entry key, its fixture spends a ring note and a default-ring note.
var entryShape = base.AnonymousEntryShapes[0]

// Every slot kind, an audit-only transfer with no pair slot, and change and dummies on the widest output count.
func TestAnonymousAuditSolvesEveryStream(t *testing.T) {
	compileAnonymous(t, base.AnonymousAuditShape{InputClass: 4, Outputs: 8})
	c := compileAnonymous(t, base.AnonymousAuditShape{InputClass: 4, Outputs: 2})
	a := ringaudit.NewAnonymousAudit(t, base.AnonymousAuditShape{InputClass: 4, Outputs: 2})
	payee := ringaudit.Recipient(t, 0, 0, 70)
	a.Outputs[0] = a.NewPayment(t, payee, inboxStream(t, a, payee, 0))
	a.Anchor, a.SenderCommitment = nil, big.NewInt(0)
	c.requireSolved(t, a.Circuit(t))
}

// The entry key opens a ring note and a default-ring note, with and without an exit.
func TestAnonymousEntrySolvesBothLayouts(t *testing.T) {
	c := compileAnonymous(t, entryShape)
	a := ringaudit.NewAnonymousAudit(t, entryShape)
	c.requireSolved(t, a.Circuit(t))
	a.Outputs[1] = ringaudit.AnonymousOutput{DeliveredOutput: a.NewExit(t, 1), Stream: ringaudit.Stream{Tag: big.NewInt(0)}}
	a.Layout.Exits = true
	c.requireSolved(t, a.Circuit(t))
}

// Every published input count solves on a commitment key and on the entry key, the data-free flag either way.
func TestAnonymousAuditSolvesEveryInputCount(t *testing.T) {
	for _, shape := range []base.AnonymousAuditShape{{InputClass: 4, Outputs: 2}, entryShape} {
		c := compileAnonymous(t, shape)
		for count := 1; count <= shape.InputClass; count++ {
			t.Run(fmt.Sprintf("%s/%d", anonymousKeyName(t, shape), count), func(t *testing.T) {
				a := ringaudit.NewAnonymousAudit(t, shape)
				if count == 1 {
					a.Inputs[1] = ringaudit.Dummy(3, big.NewInt(0x9001))
				}
				a.InputCount = count
				a.Layout.DataFree = count%2 == 0
				c.requireSolved(t, a.Circuit(t))
			})
		}
	}
}

// Each case changes one value of an honest transfer of a pair payment, an inbox payment, an exit and change in slots 0 to 3.
func TestAnonymousAuditRefusals(t *testing.T) {
	shape := base.AnonymousAuditShape{InputClass: 4, Outputs: 4}
	c := compileAnonymous(t, shape)
	payee := ringaudit.Recipient(t, 0, 0, 70)
	inbox := ringaudit.Recipient(t, 1, 1, 31)
	stranger := ringaudit.Repeat(0xc3)
	sum := func(x, y *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(x, y), ecc.BN254.ScalarField()) }
	for _, tc := range []struct {
		name   string
		mutate func(*ringaudit.AnonymousAudit)
	}{
		{"first contact with a CRDB deposit blinding", func(a *ringaudit.AnonymousAudit) {
			a.Anchor.Blinding = ringaudit.DepositBlinding(t, big.NewInt(0xd5))
		}},
		{"first tag a pair tag", func(a *ringaudit.AnonymousAudit) {
			pairTag := ringaudit.PairTag(t, ringaudit.PairKey(t, a.Anchor.SlotSecret), a.Anchor.Epoch, a.Anchor.Index)
			a.Anchor.Blinding = a.Anchor.FirstContactBlinding(t, pairTag)
		}},
		{"first tag the inbox tag of another key", func(a *ringaudit.AnonymousAudit) {
			otherTag := ringaudit.InboxTag(t, ringaudit.InboxKey(t, a.RingProgramID, inbox.RecipientKey), a.Anchor.Epoch, a.Anchor.Index)
			a.Anchor.Blinding = a.Anchor.FirstContactBlinding(t, otherTag)
		}},
		{"first contact of another owner", func(a *ringaudit.AnonymousAudit) {
			a.Anchor.Owner = spptest.MustOwnerHash(t, ringaudit.OwnerIdentity(t, stranger), payee.NullifierPk)
		}},
		// The first contact opens under the sums the anchor takes over both pair slots, so only the one pair slot bound refuses.
		{"two pair slots", func(a *ringaudit.AnonymousAudit) {
			a.Outputs[1] = a.NewPayment(t, inbox, ringaudit.Stream{Pair: true, Index: 0, Tag: a.Outputs[0].Stream.Tag})
			inboxKeys := sum(ringaudit.InboxKey(t, a.RingProgramID, payee.RecipientKey), ringaudit.InboxKey(t, a.RingProgramID, inbox.RecipientKey))
			a.Anchor.Owner = sum(a.Outputs[0].Utxo.Owner(t), a.Outputs[1].Utxo.Owner(t))
			a.Anchor.Blinding = a.Anchor.FirstContactBlinding(t, ringaudit.InboxTag(t, inboxKeys, a.Anchor.Epoch, a.Anchor.Index))
		}},
		{"slot index 64", func(a *ringaudit.AnonymousAudit) {
			a.Outputs[1] = a.NewPayment(t, inbox, inboxStream(t, *a, inbox, 64))
		}},
		{"anchor index 64", func(a *ringaudit.AnonymousAudit) { a.Anchor = a.NewAnchor(t, payee, a.Epoch-3, 64) }},
		{"anchor epoch 32 back", func(a *ringaudit.AnonymousAudit) { a.Anchor = a.NewAnchor(t, payee, a.Epoch-32, 5) }},
		{"anchor epoch ahead of the transfer", func(a *ringaudit.AnonymousAudit) { a.Anchor = a.NewAnchor(t, payee, a.Epoch+1, 5) }},
		{"self slot owned by someone else", func(a *ringaudit.AnonymousAudit) {
			change := a.Change(t, 3)
			change.OwnerKey = stranger
			a.Outputs[3] = a.NewPayment(t, change, a.Outputs[3].Stream)
		}},
		{"UTXO input at the input count", func(a *ringaudit.AnonymousAudit) { a.InputCount = 1 }},
		{"input of another owner", func(a *ringaudit.AnonymousAudit) { a.Inputs[1].OwnerPkHash = ringaudit.OwnerIdentity(t, stranger) }},
		{"input 0 a dummy", func(a *ringaudit.AnonymousAudit) { a.Inputs[0] = ringaudit.Dummy(3, big.NewInt(0x9000)) }},
		{"committed input of the default ring", func(a *ringaudit.AnonymousAudit) { a.Inputs[1] = a.SenderUtxo(t, big.NewInt(0), 60, 52) }},
		{"SeedOut omitted with an exit published", func(a *ringaudit.AnonymousAudit) { a.Layout.Exits = false }},
		{"full openings on a commitment key", func(a *ringaudit.AnonymousAudit) { a.Layout.FullOpenings = true }},
		{"escrow flag on an anonymous key", func(a *ringaudit.AnonymousAudit) { a.Layout.Escrow = true }},
		{"body encrypting another amount", func(a *ringaudit.AnonymousAudit) {
			a.Outputs[1].Body = ringaudit.SealBody(t, a.DeliveredSlotSecret(t, inbox.RecipientKey, 1), inbox.AssetAddress, inbox.Amount+1)
		}},
		{"asset not the hash of its address", func(a *ringaudit.AnonymousAudit) {
			a.Outputs[1].AssetAddress[0] ^= 1
			a.Outputs[1].Body = ringaudit.SealBody(t, a.DeliveredSlotSecret(t, inbox.RecipientKey, 1), a.Outputs[1].AssetAddress, inbox.Amount)
		}},
		{"CRRC ring secret on an anonymous ring", func(a *ringaudit.AnonymousAudit) {
			secret := ringaudit.ConfidentialRingSecret(t, a.DeliveredSlotSecret(t, inbox.RecipientKey, 1))
			a.Outputs[1].Utxo.Blinding = ringaudit.RingBlinding(t, a.FirstNullifier, secret, 1)
		}},
		{"exit blinding in TXRB form", func(a *ringaudit.AnonymousAudit) {
			a.Outputs[2].Utxo.Blinding = ringaudit.RingBlinding(t, a.FirstNullifier, big.NewInt(0x5ec), 2)
		}},
		{"recipient key given as its high-bit alias", func(a *ringaudit.AnonymousAudit) {
			alias := inbox
			alias.RecipientKey[31] |= 0x80
			a.Outputs[1] = a.NewPayment(t, alias, inboxStream(t, *a, alias, 0))
		}},
		{"sender commitment of another sender", func(a *ringaudit.AnonymousAudit) {
			a.SenderCommitment = ringaudit.SenderCommitment(t, ringaudit.OwnerIdentity(t, stranger), a.PrivateTxBlinding)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, shape)
			tc.mutate(&a)
			c.refuse(t, a.Circuit(t))
		})
	}

	// The tag of slot 1 is low248 of digest + q, the hint proposes that decomposition and the range checks refuse it.
	t.Run("tag given as its + q alias", func(t *testing.T) {
		a := ringaudit.NewAnonymousAudit(t, shape)
		digest := ringaudit.InboxTagDigest(t, ringaudit.InboxKey(t, a.RingProgramID, inbox.RecipientKey), a.Epoch, 0)
		alias := new(big.Int).Add(digest, ecc.BN254.ScalarField())
		a.Outputs[1] = a.NewPayment(t, inbox, ringaudit.Stream{Inbox: true, Index: 0, Tag: ringaudit.Low248(alias)})
		honest := registeredHint(t, "/gadget.lowBytesHint")
		forged := func(field *big.Int, inputs, outputs []*big.Int) error {
			if inputs[0].Cmp(digest) == 0 {
				return honest(field, []*big.Int{alias}, outputs)
			}
			return honest(field, inputs, outputs)
		}
		c.refuse(t, a.Circuit(t), solver.OverrideHint(solver.GetHintID(honest), forged))
	})
}

// Each case changes one value of an honest entry transfer whose input 0 is a ring note and input 1 a default-ring note.
func TestAnonymousEntryRefusals(t *testing.T) {
	c := compileAnonymous(t, entryShape)
	for _, tc := range []struct {
		name   string
		mutate func(*ringaudit.AnonymousAudit)
	}{
		{"input with a data hash", func(a *ringaudit.AnonymousAudit) { a.Inputs[1].DataHash = big.NewInt(5) }},
		{"ring note with a ring data hash", func(a *ringaudit.AnonymousAudit) { a.Inputs[0].RingDataHash = big.NewInt(5) }},
		{"input under another nullifier key than input 0", func(a *ringaudit.AnonymousAudit) {
			a.Inputs[1].NullifierPk = spptest.MustNullifierPk(t, big.NewInt(8))
		}},
		{"input hashes on an entry key", func(a *ringaudit.AnonymousAudit) { a.Layout.FullOpenings = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, entryShape)
			tc.mutate(&a)
			c.refuse(t, a.Circuit(t))
		})
	}
}

// A commitment key publishes the hash of every spent UTXO, a disclosure naming another note fails the statement.
func TestAnonymousDisclosesEachInputHash(t *testing.T) {
	shape := base.AnonymousAuditShape{InputClass: 4, Outputs: 4}
	c := compileAnonymous(t, shape)
	honest := ringaudit.NewAnonymousAudit(t, shape)
	other := honest
	other.Inputs = slices.Clone(honest.Inputs)
	other.Inputs[1].Blinding = big.NewInt(53)
	refuseOtherDisclosure(t, c, honest, other)
}

// An entry key opens every spent UTXO under input 0's nullifier key, a disclosure of another opening fails the statement.
func TestAnonymousEntryDisclosesEachOpening(t *testing.T) {
	c := compileAnonymous(t, entryShape)
	for name, edit := range map[string]func([]ringaudit.Utxo){
		"asset":         func(u []ringaudit.Utxo) { u[1].Asset = ringaudit.AssetField(t, ringaudit.Repeat(0x0b)) },
		"amount":        func(u []ringaudit.Utxo) { u[1].Amount++ },
		"blinding":      func(u []ringaudit.Utxo) { u[1].Blinding = big.NewInt(53) },
		"nullifier key": func(u []ringaudit.Utxo) { u[0].NullifierPk = big.NewInt(0x1234) },
	} {
		t.Run(name, func(t *testing.T) {
			honest := ringaudit.NewAnonymousAudit(t, entryShape)
			other := honest
			other.Inputs = slices.Clone(honest.Inputs)
			edit(other.Inputs)
			refuseOtherDisclosure(t, c, honest, other)
		})
	}
}

// An exit's asset, amount and nullifier key reach the auditor, a disclosure of another opening fails the statement.
func TestAnonymousExitDisclosesItsOpening(t *testing.T) {
	shape := base.AnonymousAuditShape{InputClass: 4, Outputs: 4}
	c := compileAnonymous(t, shape)
	for name, edit := range map[string]func(*ringaudit.Utxo){
		"asset":         func(u *ringaudit.Utxo) { u.Asset = ringaudit.AssetField(t, ringaudit.Repeat(0x0b)) },
		"amount":        func(u *ringaudit.Utxo) { u.Amount++ },
		"nullifier key": func(u *ringaudit.Utxo) { u.NullifierPk = big.NewInt(0x1234) },
	} {
		t.Run(name, func(t *testing.T) {
			honest := ringaudit.NewAnonymousAudit(t, shape)
			other := honest
			other.Outputs = slices.Clone(honest.Outputs)
			edit(&other.Outputs[2].Utxo)
			refuseOtherDisclosure(t, c, honest, other)
		})
	}
}

// refuseOtherDisclosure requires honest's statement carrying other's disclosure to fail the public input binding.
func refuseOtherDisclosure(t *testing.T, c *compiledAudit, honest, other ringaudit.AnonymousAudit) {
	t.Helper()
	statement := ringaudit.AnonymousStatement(t, honest.AuditHead(t, honest.Layout), honest.StatementOutputs(t), other.Disclosure(t), honest.Tail(t))
	c.refuseStatementOf(t, honest.Circuit(t), statement)
}

func inboxStream(t *testing.T, a ringaudit.AnonymousAudit, slot ringaudit.DeliverySlot, index uint64) ringaudit.Stream {
	t.Helper()
	tag := ringaudit.InboxTag(t, ringaudit.InboxKey(t, a.RingProgramID, slot.RecipientKey), a.Epoch, index)
	return ringaudit.Stream{Inbox: true, Index: index, Tag: tag}
}
