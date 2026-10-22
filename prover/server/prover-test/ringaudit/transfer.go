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

// Transfer is the part of a ring transfer every audit statement opens with.
type Transfer struct {
	Keys           Keys
	FirstNullifier *big.Int
	RingProgramID  *big.Int
	Salt           [16]byte
	SeedOut        *big.Int
}

// newTransfer is the fixture transfer of the default keys in the ring of program address 0x90..90.
func newTransfer(t testing.TB) Transfer {
	t.Helper()
	ringProgram := Repeat(0x90)
	tr := Transfer{
		Keys:           DefaultKeys(t),
		FirstNullifier: big.NewInt(0x1f1f),
		RingProgramID:  HashBytes(t, ringProgram[:]),
	}
	for i := range tr.Salt {
		tr.Salt[i] = 0xa0 + byte(i)
	}
	seedOut, err := protocol.OutputBlindingSeed(tr.FirstNullifier, big.NewInt(0x5eed))
	tr.SeedOut = spptest.MustHash(t, seedOut, err)
	return tr
}

// ExitBlinding is the TXOB blinding SPP derives for slot i of the transfer.
func (tr Transfer) ExitBlinding(t testing.TB, i int) *big.Int {
	t.Helper()
	return ExitBlinding(t, tr.FirstNullifier, tr.SeedOut, i)
}

// DeliveredSlotSecret is the CRDS secret of slot i keyed to the recipient u.
func (tr Transfer) DeliveredSlotSecret(t testing.TB, u [32]byte, i int) *big.Int {
	t.Helper()
	return DeliveredSlotSecret(t, tr.Keys.txViewingSk, u, tr.Salt, i, tr.FirstNullifier)
}

// AuditHead is the statement head the program builds for the transfer under layout.
func (tr Transfer) AuditHead(t testing.TB, layout Layout) AuditHead {
	t.Helper()
	head := tr.Keys.AuditHead(t, tr.FirstNullifier, tr.RingProgramID, tr.Salt)
	head.Layout = layout.Value()
	return head
}

// seedOut is SeedOut when the layout discloses it.
func (tr Transfer) seedOut(layout Layout) []*big.Int {
	if layout.Exits {
		return []*big.Int{tr.SeedOut}
	}
	return nil
}

func (tr Transfer) wires(layout Layout) base.AuditWires {
	w := base.AuditWires{FirstNullifier: tr.FirstNullifier, RingProgramID: tr.RingProgramID, SeedOut: tr.SeedOut, Layout: layout.Value()}
	setBytes(w.TxViewingSk[:], tr.Keys.txViewingSk[:])
	setBytes(w.EphSk[:], tr.Keys.ephSk[:])
	setBytes(w.AuditorPk[:], tr.Keys.auditorPk[:])
	setBytes(w.Salt[:], tr.Salt[:])
	return w
}

// DeliveredOutput is one delivered slot, the host twin of base.DeliveryWires.
type DeliveredOutput struct {
	Utxo         Utxo
	AssetAddress [32]byte
	RecipientKey [32]byte
	OwnerKey     [32]byte
	Body         [base.BodyLen]byte
}

// NewRingOutput delivers slot to its recipient key, its blinding over ringSecret of the CRDS secret.
func (tr Transfer) NewRingOutput(t testing.TB, slot DeliverySlot, ringSecret func(slotSecret *big.Int) *big.Int) DeliveredOutput {
	t.Helper()
	secret := tr.DeliveredSlotSecret(t, slot.RecipientKey, slot.Index)
	return DeliveredOutput{
		Utxo: Utxo{
			Domain: protocol.UtxoDomain, TreeID: OutputTreeID, OwnerPkHash: OwnerIdentity(t, slot.OwnerKey),
			NullifierPk: slot.NullifierPk, Asset: AssetField(t, slot.AssetAddress), Amount: slot.Amount,
			Blinding: RingBlinding(t, tr.FirstNullifier, ringSecret(secret), slot.Index),
			DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: tr.RingProgramID,
		},
		AssetAddress: slot.AssetAddress,
		RecipientKey: slot.RecipientKey,
		OwnerKey:     slot.OwnerKey,
		Body:         SealBody(t, secret, slot.AssetAddress, slot.Amount),
	}
}

// NewExit leaves the ring for the default ring, its owner published by SPP.
func (tr Transfer) NewExit(t testing.TB, i int) DeliveredOutput {
	t.Helper()
	return DeliveredOutput{Utxo: Utxo{
		Domain: protocol.UtxoDomain, TreeID: OutputTreeID, OwnerPkHash: OwnerIdentity(t, Repeat(0xe5)),
		NullifierPk: spptest.MustNullifierPk(t, big.NewInt(23)), Asset: AssetField(t, [32]byte{}), Amount: 40,
		Blinding: tr.ExitBlinding(t, i), DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0),
	}}
}

// newDummy pads a slot with random key and body bytes.
func (tr Transfer) newDummy(t testing.TB, i int) DeliveredOutput {
	t.Helper()
	d := DeliveredOutput{Utxo: Dummy(OutputTreeID, tr.ExitBlinding(t, i)), RecipientKey: Repeat(0xd1 + byte(i))}
	for j := range d.Body {
		d.Body[j] = 0xd0 + byte(j)
	}
	return d
}

// DeliverySlot names the recipient and the opening of one ring output.
type DeliverySlot struct {
	Index        int
	RecipientKey [32]byte
	OwnerKey     [32]byte
	NullifierPk  *big.Int
	AssetAddress [32]byte
	Amount       uint64
}

// Recipient is fixture recipient n, every key derived from n.
func Recipient(t testing.TB, n byte, index int, amount uint64) DeliverySlot {
	t.Helper()
	return DeliverySlot{
		Index:        index,
		RecipientKey: XPublicKey(t, Scalar(0x55+n)),
		OwnerKey:     Repeat(0xb2 + n),
		NullifierPk:  spptest.MustNullifierPk(t, big.NewInt(20+int64(n))),
		AssetAddress: Repeat(0x0a),
		Amount:       amount,
	}
}

// OutputTreeID is the fixture tree every output is appended to.
const OutputTreeID = 9

func (o DeliveredOutput) wires() base.DeliveryWires {
	w := base.DeliveryWires{Output: o.Utxo.Wires()}
	setBytes(w.AssetAddress[:], o.AssetAddress[:])
	setBytes(w.RecipientKey[:], o.RecipientKey[:])
	setBytes(w.OwnerKey[:], o.OwnerKey[:])
	setBytes(w.Body[:], o.Body[:])
	return w
}

func (o DeliveredOutput) statementOutput(t testing.TB) StatementOutput {
	t.Helper()
	return StatementOutput{Hash: o.Utxo.Hash(t), Exit: o.Utxo.isExit(), U: o.RecipientKey, Body: o.Body[:]}
}

// slotBytes mirrors base slotDisclosure, owner_key ‖ ringTail on a ring output, asset ‖ u64be(amount) on an exit.
func (o DeliveredOutput) slotBytes(t testing.TB, ringTail []byte) []byte {
	t.Helper()
	out := make([]byte, 32+len(ringTail))
	switch {
	case o.Utxo.isRingOutput():
		copy(out, slices.Concat(o.OwnerKey[:], ringTail))
	case o.Utxo.isExit():
		asset := spptest.MustFieldBytes(t, o.Utxo.Asset)
		copy(out, binary.BigEndian.AppendUint64(asset[:], o.Utxo.Amount))
	}
	return out
}
