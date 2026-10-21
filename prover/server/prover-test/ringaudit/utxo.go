package ringaudit

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Utxo is one slot opening, the host twin of base.UtxoWires.
type Utxo struct {
	Domain        int64
	TreeID        uint16
	OwnerPkHash   *big.Int
	NullifierPk   *big.Int
	Asset         *big.Int
	Amount        uint64
	Blinding      *big.Int
	DataHash      *big.Int
	RingDataHash  *big.Int
	RingProgramID *big.Int
}

// Dummy is a non-UTXO slot SPP zeroes but for its derived blinding.
func Dummy(treeID uint16, blinding *big.Int) Utxo {
	zero := big.NewInt(0)
	return Utxo{
		Domain: protocol.DummyDomain, TreeID: treeID, OwnerPkHash: zero, NullifierPk: zero, Asset: zero,
		Blinding: blinding, DataHash: zero, RingDataHash: zero, RingProgramID: zero,
	}
}

// unpublished is a slot past the published count, its opening enters no statement.
func unpublished() Utxo {
	return Dummy(0, big.NewInt(0))
}

func (u Utxo) isUtxo() bool {
	return u.Domain == protocol.UtxoDomain
}

// isExit is a UTXO leaving the ring for the default ring.
func (u Utxo) isExit() bool {
	return u.isUtxo() && u.RingProgramID.Sign() == 0
}

// isRingOutput is a UTXO that stays in a ring.
func (u Utxo) isRingOutput() bool {
	return u.isUtxo() && u.RingProgramID.Sign() != 0
}

// Owner mirrors the owner hash base opens, zero off a UTXO.
func (u Utxo) Owner(t testing.TB) *big.Int {
	t.Helper()
	if !u.isUtxo() {
		return big.NewInt(0)
	}
	return spptest.MustOwnerHash(t, u.OwnerPkHash, u.NullifierPk)
}

// Hash mirrors the slot hash base binds.
func (u Utxo) Hash(t testing.TB) *big.Int {
	t.Helper()
	return spptest.MustUtxoHash(t, protocol.Utxo{
		Domain: big.NewInt(u.Domain), Owner: u.Owner(t), Asset: u.Asset, Amount: new(big.Int).SetUint64(u.Amount),
		Blinding: u.Blinding, DataHash: u.DataHash, RingDataHash: u.RingDataHash, RingProgramID: u.RingProgramID,
	}, big.NewInt(int64(u.TreeID)))
}

// spentHash is the private_tx_hash entry of the slot, zero off a UTXO.
func (u Utxo) spentHash(t testing.TB) *big.Int {
	t.Helper()
	if !u.isUtxo() {
		return big.NewInt(0)
	}
	return u.Hash(t)
}

func (u Utxo) Wires() base.UtxoWires {
	return base.UtxoWires{
		Domain: u.Domain, TreeID: int(u.TreeID), OwnerPkHash: u.OwnerPkHash, NullifierPk: u.NullifierPk,
		Asset: u.Asset, Amount: new(big.Int).SetUint64(u.Amount), Blinding: u.Blinding,
		DataHash: u.DataHash, RingDataHash: u.RingDataHash, RingProgramID: u.RingProgramID,
	}
}

// live masks a field the disclosure opens only on a UTXO.
func live(u Utxo, value *big.Int) *big.Int {
	if !u.isUtxo() {
		return big.NewInt(0)
	}
	return value
}
