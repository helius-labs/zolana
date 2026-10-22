package base

import (
	"errors"
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Properties:
// 1. tx_viewing_sk is clamped, its tagged public key and the envelope sealing it to the auditor are statement values.
// 2. Every output slot is published and every ring output body opens for a canonical recipient key.
// 3. Every exit discloses its full opening to the auditor and carries no output data, SeedOut opens the disclosure exactly when a UTXO exits.
// 4. Every spent UTXO lies below the published input count and belongs to the hidden sender.
// 5. A commitment key discloses every spent UTXO's hash and spends notes of the ring only, an entry key opens every spent UTXO under one nullifier key with no data.
// 6. An inbox tag derives from the recipient's inbox key, a pair tag from an anchored first contact to the same owner, a change or dummy tag is free.
// 7. A ring output's blinding binds its slot secret and its published tag through CRRA and TXRB.
// 8. private_tx_hash reopens over the same slots, the sender commitment opens to the sender the inputs prove.

type AnonymousOutputWires struct {
	DeliveryWires
	Stream StreamWires
}

// StreamWires places one anonymous slot in a tag stream, a ring output takes exactly one of Inbox, Pair and Self.
type StreamWires struct {
	// Tag is low248 of the stream digest on an inbox or pair slot, free on any other slot.
	Tag   frontend.Variable
	Inbox frontend.Variable
	Pair  frontend.Variable
	// Self marks change of the hidden sender.
	Self  frontend.Variable
	Index frontend.Variable
}

// AnchorWires opens the first contact whose slot secret keys the transfer's one pair stream.
type AnchorWires struct {
	TreeID frontend.Variable
	Asset  frontend.Variable
	Amount frontend.Variable
	// SlotSecret is the first contact's CRDS slot secret, its recipient rebuilds it from its viewing key.
	SlotSecret     frontend.Variable
	FirstNullifier frontend.Variable
	SlotIndex      frontend.Variable
	Epoch          frontend.Variable
	Index          frontend.Variable
	PathIndex      frontend.Variable
	Path           [shared.StateTreeHeight]frontend.Variable
}

// AnonymousAuditCircuit is the audit of anonymous transfers, one key per shape.
type AnonymousAuditCircuit struct {
	PublicInputHash frontend.Variable   `gnark:",public"`
	Shape           AnonymousAuditShape `gnark:"-"`
	AuditWires
	Outputs           []AnonymousOutputWires
	PrivateTxHash     frontend.Variable
	PrivateTxBlinding frontend.Variable
	// SenderKey is the hidden owner's Ed25519 key.
	SenderKey [32]frontend.Variable
	// InputCount is the published nullifier count, from 1 to the input class.
	InputCount frontend.Variable
	Inputs     []UtxoWires
	// SenderCommitment is 0 on an audit-only transfer and Poseidon(CRSC, sender_pk_hash, PrivateTxBlinding) under a policy.
	SenderCommitment frontend.Variable
	// Epoch is the tag epoch the program derives from the slot.
	Epoch frontend.Variable
	// FirstContactRoot is the state root the anchor opens under, 0 without a pair slot.
	FirstContactRoot frontend.Variable
	Anchor           AnchorWires
}

type anonymousSlot struct {
	delivery
	inboxKey frontend.Variable
	stream   StreamWires
}

type spentInputs struct {
	count gadget.Count
	// hashes are the private_tx_hash input hashes, zero off a UTXO.
	hashes []frontend.Variable
	// records are each input slot's disclosure, its hash or on an entry key its asset and blinding, zero off a UTXO.
	records [][]frontend.Variable
	// amounts are u64be(amount) of every input slot on an entry key, zero off a UTXO.
	amounts []frontend.Variable
}

func NewAnonymousAuditCircuit(shape AnonymousAuditShape) (*AnonymousAuditCircuit, error) {
	if !slices.Contains(AnonymousAuditShapes[:], shape) && !slices.Contains(AnonymousEntryShapes[:], shape) {
		return nil, fmt.Errorf("base: unsupported anonymous audit shape %+v, want one of %v or %v", shape, AnonymousAuditShapes, AnonymousEntryShapes)
	}
	return &AnonymousAuditCircuit{
		Shape:   shape,
		Outputs: make([]AnonymousOutputWires, shape.Outputs),
		Inputs:  make([]UtxoWires, shape.InputClass),
	}, nil
}

func (c *AnonymousAuditCircuit) Define(api frontend.API) error {
	if err := errors.Join(
		validateLength("output", len(c.Outputs), c.Shape.Outputs),
		validateLength("input", len(c.Inputs), c.Shape.InputClass),
	); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	// 1. The envelope seals tx_viewing_sk to the auditor and the layout flags fix the published fields.
	envelope := c.sealEnvelope(api, rc)
	// No anonymous output carries data, the data-free flag holds whatever the frame sets.
	layout := decodeLayout(api, c.Layout, LayoutExits|LayoutDataFree, c.Shape.layout())
	// 2. Every ring output body opens for its recipient and every slot takes its stream, the sender hash is the owner identity of SenderKey.
	senderPkHash := gadget.SolanaOwnerIdentity(api, c.SenderKey)
	slots := make([]anonymousSlot, len(c.Outputs))
	outputSlots := make([]outputSlot, len(c.Outputs))
	for i, output := range c.Outputs {
		slots[i] = c.deliverSlot(api, rc, envelope, output, senderPkHash, i)
		outputSlots[i] = slots[i].outputSlot
	}
	// 3. SeedOut opens the disclosure exactly when an exit needs it.
	layout.assertExits(api, outputSlots)
	// 4. The anchor opens the first contact of the one pair slot.
	pairTag := c.anchor(api, rc, slots)
	var hashes, outputHashes, bodyHashes, tags, nullifierPks, slotBytes []frontend.Variable
	for i, output := range c.Outputs {
		s := slots[i]
		// 5. A proven tag derives from its stream, every ring output blinding binds its tag.
		c.assertTag(api, rc, output, s, pairTag, i)
		notExit := api.Sub(1, s.exit)
		hashes, outputHashes = append(hashes, s.Hash), append(outputHashes, api.Mul(s.Utxo, s.Hash))
		bodyHashes, tags = append(bodyHashes, s.bodyHash), append(tags, api.Mul(notExit, output.Stream.Tag))
		nullifierPks = append(nullifierPks, api.Mul(s.live, output.Output.NullifierPk))
		slotBytes = append(slotBytes, slotDisclosure(api, rc, output.DeliveryWires, s.delivery, output.RecipientKey[:])...)
	}
	// 6. Every spent UTXO is the sender's and published.
	spent := c.spend(api, senderPkHash)
	// 7. SPP's private transaction hash reopens over the same slots with no address input.
	api.AssertIsEqual(c.PrivateTxHash, shared.PrivateTxHashCircuit(api, spent.hashes, outputHashes, nil, c.PrivateTxBlinding))
	// 8. The commitment is 0 on an audit-only transfer or opens to the sender the inputs prove, the policy proof reads it.
	commitment := SenderCommitment(api, senderPkHash, c.PrivateTxBlinding)
	api.AssertIsEqual(api.Mul(c.SenderCommitment, api.Sub(c.SenderCommitment, commitment)), 0)
	// 9. Only the holder of tx_viewing_sk opens the disclosure of every output and spent UTXO.
	statement := c.statement(api, envelope,
		gadget.HashChain4(api, hashes),
		gadget.HashChain4(api, bodyHashes),
		c.disclosure(api, envelope, layout, nullifierPks, slotBytes, spent),
		gadget.HashChain4(api, tags),
	)
	// 10. The one public input commits the statement the program rebuilds.
	api.AssertIsEqual(c.PublicInputHash, statement)
	return nil
}

func (c *AnonymousAuditCircuit) deliverSlot(api frontend.API, rc frontend.Rangechecker, e auditEnvelope, o AnonymousOutputWires, senderPkHash frontend.Variable, i int) anonymousSlot {
	slot := openDelivered(api, o.DeliveryWires)
	// 1. Every ring output body opens for the holder of its canonical recipient key.
	d := c.deliver(api, e, o.DeliveryWires, slot, recipientKey(api, slot, o.RecipientKey), i)
	s := o.Stream
	// 2. Each stream flag is a bit and a ring output takes exactly one stream, any other slot none.
	api.AssertIsBoolean(s.Inbox)
	api.AssertIsBoolean(s.Pair)
	api.AssertIsBoolean(s.Self)
	api.AssertIsEqual(api.Add(s.Inbox, s.Pair, s.Self), slot.ring)
	// 3. Every stream position is below 64, the bound a recipient scans per stream and epoch.
	rc.Check(s.Index, StreamIndexBits)
	// 4. A self slot is change of the hidden sender, its tag stays free.
	gadget.AssertEqualWhen{Cond: s.Self, A: o.Output.OwnerPkHash, B: senderPkHash}.Assert(api)
	return anonymousSlot{delivery: d, inboxKey: InboxKey(api, c.RingProgramID, d.recipient), stream: s}
}

// anchor proves the pair stream's key reached the recipient and returns the pair tag digest of the pair slot.
func (c *AnonymousAuditCircuit) anchor(api frontend.API, rc frontend.Rangechecker, slots []anonymousSlot) frontend.Variable {
	a := c.Anchor
	// 1. The anchor reads the inbox key, owner and stream position of the pair slot.
	var pairs, inboxKey, owner, index frontend.Variable = 0, 0, 0, 0
	for _, s := range slots {
		pairs = api.Add(pairs, s.stream.Pair)
		inboxKey = api.Add(inboxKey, api.Mul(s.stream.Pair, s.inboxKey))
		owner = api.Add(owner, api.Mul(s.stream.Pair, s.Owner))
		index = api.Add(index, api.Mul(s.stream.Pair, s.stream.Index))
	}
	// At most one slot is pair tagged, the anchor opens one first contact.
	api.AssertIsBoolean(pairs)
	// 2. The first contact's tag is an inbox tag of the pair slot's key at a position of its stream.
	firstTag := TagField(api, rc, InboxTagDigest(api, inboxKey, a.Epoch, a.Index))
	rc.Check(api.Mul(pairs, a.Index), StreamIndexBits)
	// A pair stream lives KPairEpochs from its anchor and never before it.
	rc.Check(api.Mul(pairs, api.Sub(c.Epoch, a.Epoch)), PairEpochBits)
	// 3. Only an inbox delivery to the same owner, or that owner's own change, takes the first contact's form.
	blinding := shared.DeriveRingOutputBlinding(api, a.FirstNullifier, AnonymousRingSecret(api, a.SlotSecret, firstTag), a.SlotIndex)
	firstContact := shared.UtxoHashCircuit(api, shared.UtxoCircuitFields{
		Domain:        shared.UtxoDomain,
		Owner:         owner,
		Asset:         a.Asset,
		Amount:        a.Amount,
		Blinding:      blinding,
		DataHash:      0,
		RingDataHash:  0,
		RingProgramID: c.RingProgramID,
	}, a.TreeID)
	// 4. The first contact is a leaf of the state tree the program names, without a pair slot the root stays free.
	root := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   firstContact,
		Index:  api.ToBinary(a.PathIndex, shared.StateTreeHeight),
		Path:   a.Path[:],
		Height: shared.StateTreeHeight,
	})
	gadget.AssertEqualWhen{Cond: pairs, A: root, B: c.FirstContactRoot}.Assert(api)
	// 5. The pair key derives from the first contact's slot secret, the recipient rebuilds it from its viewing key.
	return PairTagDigest(api, PairKey(api, a.SlotSecret), c.Epoch, index)
}

// assertTag proves an inbox or pair slot's tag and binds every ring output's tag into its blinding.
func (c *AnonymousAuditCircuit) assertTag(api frontend.API, rc frontend.Rangechecker, o AnonymousOutputWires, s anonymousSlot, pairTag frontend.Variable, i int) {
	digest := api.Add(
		api.Mul(s.stream.Inbox, InboxTagDigest(api, s.inboxKey, c.Epoch, s.stream.Index)),
		api.Mul(s.stream.Pair, pairTag),
	)
	// 1. A proven tag is low248 of its stream digest, TagField refuses the bytes of digest + q.
	gadget.AssertEqualWhen{Cond: api.Add(s.stream.Inbox, s.stream.Pair), A: s.stream.Tag, B: TagField(api, rc, digest)}.Assert(api)
	// 2. The ring secret binds the published tag, an anchor reads a first contact's tag back from its blinding.
	c.assertBlinding(api, o.Output, s.outputSlot, AnonymousRingSecret(api, s.secret, s.stream.Tag), i)
}

// spend proves every spent UTXO is the hidden sender's and lies below the published count.
func (c *AnonymousAuditCircuit) spend(api frontend.API, senderPkHash frontend.Variable) spentInputs {
	// 1. The input count lies in [1, InputClass], the disclosure length fixes it as the program refuses a zero published field.
	spent := spentInputs{count: gadget.SelectCount(api, c.InputCount, 1, c.Shape.InputClass)}
	for i, input := range c.Inputs {
		opened := input.Open(api)
		// 2. An input at or past the count is no UTXO, so no spent UTXO escapes the published inputs.
		gadget.AssertZeroWhen{Cond: api.Sub(1, spent.count.Active[i]), V: opened.Utxo}.Assert(api)
		// 3. Every spent UTXO is the hidden sender's.
		gadget.AssertEqualWhen{Cond: opened.Utxo, A: input.OwnerPkHash, B: senderPkHash}.Assert(api)
		if i == 0 {
			// 4. Input 0 is a UTXO, so the disclosed sender owns a real spent UTXO.
			api.AssertIsEqual(opened.Utxo, 1)
		}
		hash := api.Mul(opened.Utxo, opened.Hash)
		spent.hashes = append(spent.hashes, hash)
		if !c.Shape.FullOpenings {
			// 5. A disclosed hash names a note of the ring, an audited output whose opening the auditor holds.
			gadget.AssertEqualWhen{Cond: opened.Utxo, A: input.RingProgramID, B: c.RingProgramID}.Assert(api)
			spent.records = append(spent.records, []frontend.Variable{hash})
			continue
		}
		// 5. The auditor rebuilds an entry input from its opening, under input 0's nullifier key and with no data.
		gadget.AssertEqualWhen{Cond: opened.Utxo, A: input.NullifierPk, B: c.Inputs[0].NullifierPk}.Assert(api)
		gadget.AssertZeroWhen{Cond: opened.Utxo, V: input.DataHash}.Assert(api)
		gadget.AssertZeroWhen{Cond: opened.Utxo, V: input.RingDataHash}.Assert(api)
		spent.amounts = append(spent.amounts, uintBytes(api, api.Mul(opened.Utxo, input.Amount), 8)...)
		spent.records = append(spent.records, []frontend.Variable{api.Mul(opened.Utxo, input.Asset), api.Mul(opened.Utxo, input.Blinding)})
	}
	return spent
}

// disclosure is the anonymous disclosure the layout selects, mirrored by DisclosureLayout::Anonymous in custom-rings/interface/src/disclosure.rs.
//
//	SeedOut under LayoutExits, then on a commitment key
//	nullifier_pk per output, pack_disclosure(sender_key ‖ slot bytes per output), hash per published input
//	and on an entry key
//	sender nullifier_pk, nullifier_pk per output, pack_disclosure(sender_key ‖ slot bytes per output),
//	pack_disclosure(u64be(amount) per input slot), asset and blinding per published input
func (c *AnonymousAuditCircuit) disclosure(api frontend.API, e auditEnvelope, layout auditLayout, nullifierPks, slotBytes []frontend.Variable, spent spentInputs) frontend.Variable {
	// SolanaOwnerIdentity bounds the sender key bytes, deliverSlot and slotDisclosure the slot bytes.
	head := slices.Concat(nullifierPks, PackDisclosure(api, slices.Concat(c.SenderKey[:], slotBytes)))
	if c.Shape.FullOpenings {
		// Input 0 is a UTXO, its key is the key of every spent UTXO.
		head = slices.Concat([]frontend.Variable{c.Inputs[0].NullifierPk}, head, PackDisclosure(api, spent.amounts))
	}
	return e.disclose(api, layout.choices(api, LayoutExits), func(choice layoutChoice) disclosureLayout {
		return choice.counted(api, slices.Concat(c.seedOut(choice), head), spent.records, spent.count)
	})
}

// statement is the anonymous audit preimage, mirrored by AuditStatement::elements under AuditKind::Anonymous in custom-rings/interface/src/statement.rs.
//
//	head ‖ output_chain, body_chain, disclosure_chain, private_tx_hash, tag_chain, epoch, first_contact_root, sender_commitment
func (c *AnonymousAuditCircuit) statement(api frontend.API, e auditEnvelope, outputChain, bodyChain, disclosureChain, tagChain frontend.Variable) frontend.Variable {
	return gadget.HashChain4(api, append(e.statementHead(c.AuditWires),
		outputChain, bodyChain, disclosureChain, c.PrivateTxHash, tagChain, c.Epoch, c.FirstContactRoot, c.SenderCommitment,
	))
}
