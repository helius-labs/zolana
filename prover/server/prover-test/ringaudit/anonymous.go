package ringaudit

import (
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Stream is the host twin of base.StreamWires.
type Stream struct {
	Tag   *big.Int
	Inbox bool
	Pair  bool
	Self  bool
	Index uint64
}

type AnonymousOutput struct {
	DeliveredOutput
	Stream Stream
}

// Anchor is the first contact of the pair slot and its place in the state tree.
type Anchor struct {
	// Owner is the owner hash the first contact commits.
	Owner          *big.Int
	TreeID         uint16
	Asset          *big.Int
	Amount         uint64
	Blinding       *big.Int
	SlotSecret     *big.Int
	FirstNullifier *big.Int
	SlotIndex      int
	Epoch          uint64
	Index          uint64
	LeafIndex      uint64
}

// AnonymousAudit is an anonymous audit witness with every derived value explicit, the statement rebuilds from its fields.
type AnonymousAudit struct {
	Transfer
	Shape             base.AnonymousAuditShape
	Outputs           []AnonymousOutput
	SenderKey         [32]byte
	SenderNullifierPk *big.Int
	PrivateTxBlinding *big.Int
	// SenderCommitment is 0 on an audit-only transfer.
	SenderCommitment *big.Int
	Epoch            uint64
	InputCount       int
	Inputs           []Utxo
	// Anchor is nil without a pair slot.
	Anchor *Anchor
	Layout Layout
}

// Fixture streams of the anonymous outputs, by output count.
const (
	kindPair = iota
	kindInbox
	kindSelf
	kindExit
	kindDummy
)

var anonymousOutputs = map[int][]int{
	2: {kindPair, kindSelf},
	4: {kindPair, kindInbox, kindExit, kindSelf},
	8: {kindPair, kindInbox, kindInbox, kindExit, kindSelf, kindInbox, kindDummy, kindDummy},
}

// NewAnonymousAudit spends two sender UTXOs into the anonymousOutputs slots of its output count, input 1 a default-ring note on an entry shape.
func NewAnonymousAudit(t testing.TB, shape base.AnonymousAuditShape) AnonymousAudit {
	t.Helper()
	a := AnonymousAudit{
		Transfer:          newTransfer(t),
		Shape:             shape,
		SenderKey:         Repeat(0xa1),
		SenderNullifierPk: spptest.MustNullifierPk(t, big.NewInt(7)),
		PrivateTxBlinding: big.NewInt(0x5b1d),
		Epoch:             1000,
		InputCount:        2,
	}
	a.SenderCommitment = SenderCommitment(t, a.SenderPkHash(t), a.PrivateTxBlinding)
	a.Inputs = make([]Utxo, shape.InputClass)
	for i := range a.Inputs {
		a.Inputs[i] = Dummy(3, big.NewInt(0x9000+int64(i)))
	}
	a.Inputs[0] = a.SenderUtxo(t, a.RingProgramID, 100, 51)
	a.Inputs[1] = a.SenderUtxo(t, a.RingProgramID, 60, 52)
	if shape.FullOpenings {
		a.Inputs[1] = a.SenderUtxo(t, big.NewInt(0), 60, 52)
	}

	payee := Recipient(t, 0, 0, 0)
	a.Anchor = a.NewAnchor(t, payee, a.Epoch-3, 5)
	inboxes := uint64(0)
	for i, kind := range anonymousOutputs[shape.Outputs] {
		switch kind {
		case kindPair:
			slot := Recipient(t, 0, i, 70)
			a.Outputs = append(a.Outputs, a.NewPayment(t, slot, Stream{Pair: true, Index: 2, Tag: PairTag(t, PairKey(t, a.Anchor.SlotSecret), a.Epoch, 2)}))
		case kindInbox:
			slot := Recipient(t, 1+byte(inboxes%2), i, 30+uint64(i))
			stream := Stream{Inbox: true, Index: inboxes, Tag: InboxTag(t, InboxKey(t, a.RingProgramID, slot.RecipientKey), a.Epoch, inboxes)}
			a.Outputs = append(a.Outputs, a.NewPayment(t, slot, stream))
			inboxes++
		case kindSelf:
			a.Outputs = append(a.Outputs, a.NewPayment(t, a.Change(t, i), Stream{Self: true, Tag: Low248(big.NewInt(0xc4a9e))}))
		case kindExit:
			a.Outputs = append(a.Outputs, AnonymousOutput{DeliveredOutput: a.NewExit(t, i), Stream: Stream{Tag: big.NewInt(0)}})
		case kindDummy:
			a.Outputs = append(a.Outputs, AnonymousOutput{DeliveredOutput: a.newDummy(t, i), Stream: Stream{Tag: Low248(big.NewInt(0xd0d0 + int64(i)))}})
		}
	}
	a.Layout = Layout{Exits: hasExit(deliveredUtxos(a.Outputs)), FullOpenings: shape.FullOpenings}
	return a
}

// SenderPkHash is the owner identity of the hidden sender.
func (a AnonymousAudit) SenderPkHash(t testing.TB) *big.Int {
	t.Helper()
	return spptest.MustSolanaPkField(t, a.SenderKey)
}

// SenderUtxo is a UTXO of the hidden sender in the given ring, 0 for the default ring.
func (a AnonymousAudit) SenderUtxo(t testing.TB, ringID *big.Int, amount uint64, blinding int64) Utxo {
	t.Helper()
	return Utxo{
		Domain: protocol.UtxoDomain, TreeID: 3, OwnerPkHash: a.SenderPkHash(t), NullifierPk: a.SenderNullifierPk,
		Asset: AssetField(t, Repeat(0x0a)), Amount: amount, Blinding: big.NewInt(blinding),
		DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: ringID,
	}
}

// Change is the sender's change slot i, delivered to its change key.
func (a AnonymousAudit) Change(t testing.TB, i int) DeliverySlot {
	t.Helper()
	return DeliverySlot{
		Index: i, RecipientKey: XPublicKey(t, Scalar(0x66)), OwnerKey: a.SenderKey,
		NullifierPk: a.SenderNullifierPk, AssetAddress: Repeat(0x0a), Amount: 15,
	}
}

// NewPayment delivers a ring output whose blinding binds stream.Tag.
func (a AnonymousAudit) NewPayment(t testing.TB, slot DeliverySlot, stream Stream) AnonymousOutput {
	t.Helper()
	return AnonymousOutput{
		DeliveredOutput: a.NewRingOutput(t, slot, func(secret *big.Int) *big.Int { return AnonymousRingSecret(t, secret, stream.Tag) }),
		Stream:          stream,
	}
}

// NewAnchor is an earlier inbox delivery to the payee, epoch and index placing its inbox tag.
func (a AnonymousAudit) NewAnchor(t testing.TB, payee DeliverySlot, epoch, index uint64) *Anchor {
	t.Helper()
	earlier := a.Transfer
	earlier.Keys = earlier.Keys.WithRawTxScalar(t, Clamped(Scalar(0x44)))
	earlier.FirstNullifier = big.NewInt(0x2f2f)
	anchor := &Anchor{
		TreeID:         4,
		Asset:          AssetField(t, Repeat(0x0a)),
		Amount:         7,
		SlotSecret:     earlier.DeliveredSlotSecret(t, payee.RecipientKey, 1),
		FirstNullifier: earlier.FirstNullifier,
		SlotIndex:      1,
		Epoch:          epoch,
		Index:          index,
		LeafIndex:      37,
	}
	anchor.Owner = spptest.MustOwnerHash(t, spptest.MustSolanaPkField(t, payee.OwnerKey), payee.NullifierPk)
	anchor.Blinding = anchor.FirstContactBlinding(t, InboxTag(t, InboxKey(t, a.RingProgramID, payee.RecipientKey), epoch, index))
	return anchor
}

// FirstContactBlinding is the anonymous ring output blinding of the first contact under its first tag.
func (anchor Anchor) FirstContactBlinding(t testing.TB, firstTag *big.Int) *big.Int {
	t.Helper()
	return RingBlinding(t, anchor.FirstNullifier, AnonymousRingSecret(t, anchor.SlotSecret, firstTag), anchor.SlotIndex)
}

// FirstContactRoot is the state root holding the first contact, 0 without an anchor.
func (a AnonymousAudit) FirstContactRoot(t testing.TB) *big.Int {
	t.Helper()
	if a.Anchor == nil {
		return big.NewInt(0)
	}
	root, _ := a.firstContactTree(t)
	return root
}

func (a AnonymousAudit) firstContactTree(t testing.TB) (*big.Int, protocol.StateTreeWitness) {
	t.Helper()
	leaf := spptest.MustUtxoHash(t, protocol.Utxo{
		Domain: big.NewInt(protocol.UtxoDomain), Owner: a.Anchor.Owner, Asset: a.Anchor.Asset,
		Amount: new(big.Int).SetUint64(a.Anchor.Amount), Blinding: a.Anchor.Blinding,
		DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: a.RingProgramID,
	}, big.NewInt(int64(a.Anchor.TreeID)))
	root, proofs := spptest.MustBuildSparseStateTree(t, map[uint64]*big.Int{a.Anchor.LeafIndex: leaf})
	return root, proofs[a.Anchor.LeafIndex]
}

// PrivateTxHash is SPP's private transaction hash over the slots, with no address input.
func (a AnonymousAudit) PrivateTxHash(t testing.TB) *big.Int {
	t.Helper()
	return spptest.MustPrivateTxHash(t, spentHashes(t, a.Inputs), spentHashes(t, deliveredUtxos(a.Outputs)), nil, a.PrivateTxBlinding)
}

// Statement mirrors the anonymous audit preimage, head ‖ output_chain, body_chain, disclosure_chain,
// private_tx_hash, tag_chain, epoch, first_contact_root, sender_commitment.
func (a AnonymousAudit) Statement(t testing.TB) []*big.Int {
	t.Helper()
	return AnonymousStatement(t, a.AuditHead(t, a.Layout), a.StatementOutputs(t), a.Disclosure(t), a.Tail(t))
}

func (a AnonymousAudit) Tail(t testing.TB) AnonymousTail {
	t.Helper()
	return AnonymousTail{
		PrivateTxHash:    a.PrivateTxHash(t),
		Epoch:            a.Epoch,
		FirstContactRoot: a.FirstContactRoot(t),
		SenderCommitment: a.SenderCommitment,
	}
}

func (a AnonymousAudit) StatementOutputs(t testing.TB) []StatementOutput {
	t.Helper()
	outputs := make([]StatementOutput, len(a.Outputs))
	for i, output := range a.Outputs {
		outputs[i] = output.statementOutput(t)
		outputs[i].Tag = output.Stream.Tag
	}
	return outputs
}

// Disclosure is the enciphered anonymous disclosure under a.Layout, input hashes or on an entry shape full input openings.
func (a AnonymousAudit) Disclosure(t testing.TB) []*big.Int {
	t.Helper()
	var nullifierPks []*big.Int
	slotBytes := slices.Clone(a.SenderKey[:])
	for _, output := range a.Outputs {
		nullifierPks = append(nullifierPks, live(output.Utxo, output.Utxo.NullifierPk))
		slotBytes = append(slotBytes, output.slotBytes(t, output.RecipientKey[:])...)
	}
	head := slices.Concat(nullifierPks, PackDisclosure(slotBytes))
	var records []*big.Int
	published := a.Inputs[:a.InputCount]
	if a.Layout.FullOpenings {
		var amounts []byte
		for _, input := range a.Inputs {
			amounts = binary.BigEndian.AppendUint64(amounts, live(input, new(big.Int).SetUint64(input.Amount)).Uint64())
		}
		head = slices.Concat([]*big.Int{a.Inputs[0].NullifierPk}, head, PackDisclosure(amounts))
		for _, input := range published {
			records = append(records, live(input, input.Asset), live(input, input.Blinding))
		}
	} else {
		records = spentHashes(t, published)
	}
	return a.Keys.Disclose(t, a.Salt, slices.Concat(a.seedOut(a.Layout), head, records))
}

// Circuit is the base assignment proving the statement.
func (a AnonymousAudit) Circuit(t testing.TB) *base.AnonymousAuditCircuit {
	t.Helper()
	c, err := base.NewAnonymousAuditCircuit(a.Shape)
	if err != nil {
		t.Fatal(err)
	}
	c.PublicInputHash = spptest.MustHashChain4(t, a.Statement(t))
	c.AuditWires = a.wires(a.Layout)
	for i, output := range a.Outputs {
		c.Outputs[i] = base.AnonymousOutputWires{DeliveryWires: output.wires(), Stream: base.StreamWires{
			Tag: output.Stream.Tag, Inbox: spptest.Bit(output.Stream.Inbox), Pair: spptest.Bit(output.Stream.Pair),
			Self: spptest.Bit(output.Stream.Self), Index: output.Stream.Index,
		}}
	}
	c.PrivateTxHash = a.PrivateTxHash(t)
	c.PrivateTxBlinding = a.PrivateTxBlinding
	setBytes(c.SenderKey[:], a.SenderKey[:])
	c.InputCount = a.InputCount
	for i, input := range a.Inputs {
		c.Inputs[i] = input.Wires()
	}
	c.SenderCommitment = a.SenderCommitment
	c.Epoch = a.Epoch
	c.FirstContactRoot = a.FirstContactRoot(t)
	c.Anchor = a.anchorWires(t)
	return c
}

// anchorWires opens the first contact, zero without an anchor.
func (a AnonymousAudit) anchorWires(t testing.TB) base.AnchorWires {
	t.Helper()
	w := base.AnchorWires{TreeID: 0, Asset: 0, Amount: 0, SlotSecret: 0, FirstNullifier: 0, SlotIndex: 0, Epoch: 0, Index: 0, PathIndex: 0}
	for i := range w.Path {
		w.Path[i] = 0
	}
	if a.Anchor == nil {
		return w
	}
	_, proof := a.firstContactTree(t)
	w = base.AnchorWires{
		TreeID: int(a.Anchor.TreeID), Asset: a.Anchor.Asset, Amount: a.Anchor.Amount, SlotSecret: a.Anchor.SlotSecret,
		FirstNullifier: a.Anchor.FirstNullifier, SlotIndex: a.Anchor.SlotIndex, Epoch: a.Anchor.Epoch, Index: a.Anchor.Index,
		PathIndex: proof.PathIndex,
	}
	for i, sibling := range proof.PathElements {
		w.Path[i] = sibling
	}
	return w
}

func deliveredUtxos(outputs []AnonymousOutput) []Utxo {
	utxos := make([]Utxo, len(outputs))
	for i, output := range outputs {
		utxos[i] = output.Utxo
	}
	return utxos
}

func spentHashes(t testing.TB, utxos []Utxo) []*big.Int {
	t.Helper()
	hashes := make([]*big.Int, len(utxos))
	for i, utxo := range utxos {
		hashes[i] = utxo.spentHash(t)
	}
	return hashes
}
