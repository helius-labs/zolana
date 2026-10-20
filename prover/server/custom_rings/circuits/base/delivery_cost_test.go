package base

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

// deliveryCostCircuit repeats one witnessed delivery slot Slots times under a witnessed transaction key.
type deliveryCostCircuit struct {
	TxViewingSk [32]frontend.Variable
	TxPk        [2]frontend.Variable
	Salt        frontend.Variable
	Viewing     [33]frontend.Variable
	Note        AuditUtxoWires
	Output      DeliveryWires
	Slots       int  `gnark:"-"`
	Padding     bool `gnark:"-"`
}

func (c *deliveryCostCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	keys := auditKeys{txSk: c.TxViewingSk, txPk: c.TxPk[:], salt: c.Salt}
	anonymous := frontend.Variable(1)
	if c.Padding {
		anonymous = 0
	}
	for i := range c.Slots {
		_ = c.Output.define(api, rc, keys, deliverySlot{index: i, note: c.Note, viewing: c.Viewing, anonymous: anonymous, active: 1, ringHash: 0})
	}
	return nil
}

// The first slot pays the shared lookup tables, the second slot is the marginal price of one output.
func TestDeliveryCostPerSlot(t *testing.T) {
	one := auditConstraintCount(t, &deliveryCostCircuit{Slots: 1})
	real := auditConstraintCount(t, &deliveryCostCircuit{Slots: 2}) - one
	padding := auditConstraintCount(t, &deliveryCostCircuit{Slots: 2, Padding: true}) - auditConstraintCount(t, &deliveryCostCircuit{Slots: 1, Padding: true})
	t.Logf("tables_and_first_slot=%d real_slot=%d padding_slot=%d", one, real, padding)
	const pinnedReal, pinnedPadding = 33403, 33015
	if real != pinnedReal || padding != pinnedPadding {
		t.Fatalf("real slot %d and padding slot %d differ from the pinned %d and %d", real, padding, pinnedReal, pinnedPadding)
	}
}
