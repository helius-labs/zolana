package base_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringkey"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func compileDelivered(t *testing.T) *compiledAudit {
	t.Helper()
	circuit, err := base.NewDeliveredAuditCircuit(8)
	if err != nil {
		t.Fatal(err)
	}
	return compileAudit(t, ringkey.Name(t, common.RingDeliveredAudit, 0, 8), circuit, ringaudit.NewDeliveredAudit(t, 8).Circuit(t))
}

// Each case changes one value of an honest transfer whose slot 0 is a ring output, slot 6 the exit and slot 7 a dummy.
func TestDeliveredAuditRefusals(t *testing.T) {
	c := compileDelivered(t)
	slot := ringaudit.Recipient(t, 0, 0, 100)
	for _, tc := range []struct {
		name   string
		mutate func(*ringaudit.DeliveredAudit)
	}{
		{"ring output with a data hash", func(d *ringaudit.DeliveredAudit) { d.Outputs[0].Utxo.DataHash = big.NewInt(5) }},
		{"exit with a ring data hash", func(d *ringaudit.DeliveredAudit) { d.Outputs[6].Utxo.RingDataHash = big.NewInt(5) }},
		{"body encrypting another amount", func(d *ringaudit.DeliveredAudit) {
			d.Outputs[0].Body = ringaudit.SealBody(t, d.DeliveredSlotSecret(t, slot.RecipientKey, 0), slot.AssetAddress, slot.Amount+1)
		}},
		{"asset not the hash of its address", func(d *ringaudit.DeliveredAudit) {
			d.Outputs[0].AssetAddress[0] ^= 1
			d.Outputs[0].Body = ringaudit.SealBody(t, d.DeliveredSlotSecret(t, slot.RecipientKey, 0), d.Outputs[0].AssetAddress, slot.Amount)
		}},
		{"CRRA ring secret on a confidential ring", func(d *ringaudit.DeliveredAudit) {
			secret := ringaudit.AnonymousRingSecret(t, d.DeliveredSlotSecret(t, slot.RecipientKey, 0), big.NewInt(0x7a6))
			d.Outputs[0].Utxo.Blinding = ringaudit.RingBlinding(t, d.FirstNullifier, secret, 0)
		}},
		{"exit blinding in TXRB form", func(d *ringaudit.DeliveredAudit) {
			d.Outputs[6].Utxo.Blinding = ringaudit.RingBlinding(t, d.FirstNullifier, big.NewInt(0x5ec), 6)
		}},
		{"owner key not the slot owner", func(d *ringaudit.DeliveredAudit) { d.Outputs[0].OwnerKey[0] ^= 1 }},
		{"recipient key given as its high-bit alias", func(d *ringaudit.DeliveredAudit) {
			alias := slot
			alias.RecipientKey[31] |= 0x80
			d.Outputs[0] = d.NewRingOutput(t, alias, func(secret *big.Int) *big.Int { return ringaudit.ConfidentialRingSecret(t, secret) })
		}},
		{"dense slots with an exit published", func(d *ringaudit.DeliveredAudit) { d.Layout.Exits = false }},
		{"SeedOut published without an exit", func(d *ringaudit.DeliveredAudit) {
			*d = ringaudit.DeliveredAuditOf(t, 8)
			d.Layout.Exits = true
		}},
		{"full openings flag on a delivered key", func(d *ringaudit.DeliveredAudit) { d.Layout.FullOpenings = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := ringaudit.NewDeliveredAudit(t, 8)
			tc.mutate(&d)
			c.refuse(t, d.Circuit(t))
		})
	}

	// The program reads key escrow off the config, a disclosure without nullifier keys fails a statement that clears it.
	t.Run("nullifier keys omitted with the escrow bit clear", func(t *testing.T) {
		d := ringaudit.NewDeliveredAudit(t, 8)
		escrowed := d
		escrowed.Layout.Escrow = true
		c.refuseStatementOf(t, d.Circuit(t),
			ringaudit.DeliveredStatement(t, d.AuditHead(t, d.Layout), d.StatementOutputs(t), escrowed.Disclosure(t)))
	})
}

// Every flag value solves, an exit-free transfer with dense slots and the data-free flag a delivered key ignores.
func TestDeliveredAuditSolvesEveryLayout(t *testing.T) {
	c := compileDelivered(t)
	deliveredFlags := base.LayoutExits | base.LayoutEscrow | base.LayoutDataFree
	for value := range deliveredFlags + 1 {
		layout := ringaudit.Layout{Exits: value&base.LayoutExits != 0, Escrow: value&base.LayoutEscrow != 0, DataFree: value&base.LayoutDataFree != 0}
		t.Run(fmt.Sprintf("%+v", layout), func(t *testing.T) {
			d := ringaudit.DeliveredAuditOf(t, 8)
			if layout.Exits {
				d = ringaudit.NewDeliveredAudit(t, 8)
			}
			d.Layout = layout
			c.requireSolved(t, d.Circuit(t))
		})
	}
}
