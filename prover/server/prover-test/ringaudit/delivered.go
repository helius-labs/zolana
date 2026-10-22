package ringaudit

import (
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// DeliveredAudit is a delivered confidential audit witness with every derived value explicit.
type DeliveredAudit struct {
	Transfer
	Outputs []DeliveredOutput
	Layout  Layout
}

// NewDeliveredAudit fills capacity slots with ring outputs, then one exit and one dummy.
func NewDeliveredAudit(t testing.TB, capacity int) DeliveredAudit {
	t.Helper()
	return DeliveredAuditOf(t, capacity, capacity-2)
}

// DeliveredAuditOf delivers ring outputs to every slot but the exits and a last dummy.
func DeliveredAuditOf(t testing.TB, capacity int, exits ...int) DeliveredAudit {
	t.Helper()
	d := DeliveredAudit{Transfer: newTransfer(t), Outputs: make([]DeliveredOutput, capacity)}
	for i := range capacity {
		switch {
		case i == capacity-1:
			d.Outputs[i] = d.newDummy(t, i)
		case slices.Contains(exits, i):
			d.Outputs[i] = d.NewExit(t, i)
		default:
			d.Outputs[i] = d.NewConfidentialOutput(t, i)
		}
	}
	d.Layout.Exits = len(exits) > 0
	return d
}

// NewConfidentialOutput delivers slot i to fixture recipient i mod 3 under its CRRC ring secret.
func (d DeliveredAudit) NewConfidentialOutput(t testing.TB, i int) DeliveredOutput {
	t.Helper()
	return d.NewRingOutput(t, Recipient(t, byte(i%3), i, 100+uint64(i)), func(secret *big.Int) *big.Int {
		return ConfidentialRingSecret(t, secret)
	})
}

// Statement mirrors the delivered audit preimage, head ‖ output_chain, body_chain, disclosure_chain, recipient_key_chain.
func (d DeliveredAudit) Statement(t testing.TB) []*big.Int {
	t.Helper()
	return DeliveredStatement(t, d.AuditHead(t, d.Layout), d.StatementOutputs(t), d.Disclosure(t))
}

func (d DeliveredAudit) StatementOutputs(t testing.TB) []StatementOutput {
	t.Helper()
	outputs := make([]StatementOutput, len(d.Outputs))
	for i, output := range d.Outputs {
		outputs[i] = output.statementOutput(t)
	}
	return outputs
}

// Disclosure is the enciphered delivered disclosure under d.Layout, slots without their 8 tail bytes on an exit-free transfer.
func (d DeliveredAudit) Disclosure(t testing.TB) []*big.Int {
	t.Helper()
	var nullifierPks []*big.Int
	var slotBytes []byte
	for _, output := range d.Outputs {
		if !d.Layout.Escrow {
			nullifierPks = append(nullifierPks, live(output.Utxo, output.Utxo.NullifierPk))
		}
		bytes := output.slotBytes(t, make([]byte, 8))
		if !d.Layout.Exits {
			bytes = bytes[:32]
		}
		slotBytes = append(slotBytes, bytes...)
	}
	return d.Keys.Disclose(t, d.Salt, slices.Concat(d.seedOut(d.Layout), nullifierPks, PackDisclosure(slotBytes)))
}

// Circuit is the base assignment proving the statement.
func (d DeliveredAudit) Circuit(t testing.TB) *base.DeliveredAuditCircuit {
	t.Helper()
	c, err := base.NewDeliveredAuditCircuit(len(d.Outputs))
	if err != nil {
		t.Fatal(err)
	}
	c.PublicInputHash = spptest.MustHashChain4(t, d.Statement(t))
	c.AuditWires = d.wires(d.Layout)
	for i, output := range d.Outputs {
		c.Outputs[i] = output.wires()
	}
	return c
}
