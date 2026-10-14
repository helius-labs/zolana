package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// VelocityRowWires caps one asset's outflow and sets its co-sign threshold, zero turns either off.
type VelocityRowWires struct {
	Asset       frontend.Variable
	Cap         frontend.Variable
	CosignAbove frontend.Variable
}

// RecordWires opens the predecessor spend record, its counters only inside the current window.
type RecordWires struct {
	Version    frontend.Variable
	Window     frontend.Variable
	Commitment frontend.Variable
	Salt       frontend.Variable
	Assets     [NVelocityAssets]frontend.Variable
	Spent      [NVelocityAssets]frontend.Variable
	// Each successor needs a fresh salt.
	NextSalt frontend.Variable
}

type velocityPolicy struct {
	windowEnabled frontend.Variable
	rows          base.Count
}

// A window needs at least one row, rows hold distinct assets and zero padding.
func (c *CustomRingPolicyCircuit) checkVelocityTable(api frontend.API, rc frontend.Rangechecker) velocityPolicy {
	rows := base.SelectCount(api, c.VelocityCount, 0, NVelocityAssets+1)
	rc.Check(c.WindowSlots, amountBits)
	windowEnabled := base.NonZero(api, c.WindowSlots)
	api.AssertIsEqual(api.Mul(windowEnabled, rows.OneHot[0]), 0)
	for i, row := range c.Velocity {
		rc.Check(row.Cap, amountBits)
		rc.Check(row.CosignAbove, amountBits)
		shared.AssertWhen(api, rows.Active[i], base.NonZero(api, row.Asset))
		shared.AssertWhen(api, rows.Active[i], base.NonZero(api, api.Add(row.Cap, row.CosignAbove)))
		padding := api.Sub(1, rows.Active[i])
		for _, value := range []frontend.Variable{row.Asset, row.Cap, row.CosignAbove} {
			api.AssertIsEqual(api.Mul(padding, value), 0)
		}
		for j, other := range c.Velocity[:i] {
			shared.AssertWhen(api, api.Mul(rows.Active[i], rows.Active[j]), base.NonZero(api, api.Sub(row.Asset, other.Asset)))
		}
	}
	return velocityPolicy{windowEnabled: windowEnabled, rows: rows}
}

// Outflow counts every live input of the single sender, less change returned to the sender inside the ring.
func (c *CustomRingPolicyCircuit) constrainVelocity(api frontend.API, rc frontend.Rangechecker, policy velocityPolicy, tx transaction) successorCounters {
	rowsEnabled := api.Sub(1, policy.rows.OneHot[0])
	api.AssertIsEqual(tx.inputs[0].record, 0)
	shared.AssertWhen(api, rowsEnabled, tx.inputs[0].live)
	sender := tx.inputs[0].ownerPkHash
	for _, input := range tx.inputs[1:] {
		shared.AssertWhen(api, api.Mul(rowsEnabled, input.live), api.IsZero(api.Sub(input.ownerPkHash, sender)))
	}
	// Windowed spends must not use the namespace to claim addresses.
	api.AssertIsEqual(api.Mul(policy.windowEnabled, c.AddressChain), 0)

	rc.Check(c.Record.Version, amountBits)
	rc.Check(c.Record.Window, amountBits)
	rc.Check(c.WindowIndex, amountBits)
	shared.AssertWhen(api, policy.windowEnabled, outputTotalAtMost(api, c.Record.Window, c.WindowIndex))
	shared.AssertWhen(api, api.Sub(1, policy.windowEnabled), api.IsZero(c.WindowIndex))
	sameWindow := api.IsZero(api.Sub(c.Record.Window, c.WindowIndex))
	seed := gadget.PoseidonHash(api, []frontend.Variable{SpendAddressDomain, sender})
	address := entryAddress(api, c.NamespaceOwnerHash, seed, c.AddressTreeID)
	predecessor := spendRecord(api, address, sender, c.Record.Version, c.Record.Window, c.Record.Commitment)
	for i, slot := range c.Inputs {
		c.assertRecord(api, slot, tx.inputs[i], predecessor)
	}
	for _, spent := range c.Record.Spent {
		rc.Check(spent, amountBits)
	}
	opened := countersCommitment(api, c.Record.Salt, c.Record.Assets[:], c.Record.Spent[:])
	api.AssertIsEqual(api.Mul(policy.windowEnabled, sameWindow, api.Sub(opened, c.Record.Commitment)), 0)

	approval := frontend.Variable(0)
	next := successorCounters{salt: c.Record.NextSalt}
	for r, row := range c.Velocity {
		inflow, change := frontend.Variable(0), frontend.Variable(0)
		for _, input := range tx.inputs {
			inflow = api.Add(inflow, api.Mul(input.live, api.IsZero(api.Sub(input.asset, row.Asset)), input.amount))
		}
		for _, output := range tx.outputs {
			toSender := api.Mul(api.IsZero(api.Sub(output.ownerPkHash, sender)), api.IsZero(api.Sub(output.ringProgramID, c.RingID)))
			change = api.Add(change, api.Mul(output.live, api.IsZero(api.Sub(output.asset, row.Asset)), toSender, output.amount))
		}
		shared.AssertWhen(api, policy.rows.Active[r], outputTotalAtMost(api, change, inflow))
		outflow := api.Sub(inflow, change)
		previous := frontend.Variable(0)
		for k, asset := range c.Record.Assets {
			previous = api.Add(previous, api.Mul(api.IsZero(api.Sub(asset, row.Asset)), c.Record.Spent[k]))
		}
		// A row without a cap keeps a zero counter, so co-signing alone never accumulates.
		capped := api.Mul(policy.rows.Active[r], base.NonZero(api, row.Cap))
		spent := api.Mul(capped, api.Add(api.Mul(policy.windowEnabled, sameWindow, previous), outflow))
		rc.Check(spent, amountBits)
		shared.AssertWhen(api, capped, outputTotalAtMost(api, spent, row.Cap))
		cosigned := api.Mul(policy.rows.Active[r], base.NonZero(api, row.CosignAbove))
		approval = api.Or(approval, api.Mul(cosigned, api.Sub(1, outputTotalAtMost(api, outflow, row.CosignAbove))))
		next.assets[r], next.spent[r] = row.Asset, spent
	}
	api.AssertIsBoolean(c.ApprovalRequired)
	api.AssertIsEqual(c.ApprovalRequired, approval)

	// The successor version stays a u64 while a window is on.
	version := api.Add(c.Record.Version, 1)
	rc.Check(api.Mul(policy.windowEnabled, version), amountBits)
	successor := spendRecord(api, address, sender, version, c.WindowIndex, countersCommitment(api, next.salt, next.assets[:], next.spent[:]))
	for i, slot := range c.Outputs {
		c.assertRecord(api, slot.UtxoWires, tx.outputs[i], successor)
	}
	return next
}

// assertRecord pins the record slot to the namespace owner's spend record UTXO.
func (c *CustomRingPolicyCircuit) assertRecord(api frontend.API, w UtxoWires, view utxoView, dataHash frontend.Variable) {
	for _, pair := range [][2]frontend.Variable{
		{w.Domain, shared.UtxoDomain}, {view.owner, c.NamespaceOwnerHash}, {w.Asset, solAssetField}, {w.Amount, 0},
		{w.RingDataHash, 0}, {w.RingProgramID, 0}, {w.DataHash, dataHash},
	} {
		api.AssertIsEqual(api.Mul(view.record, api.Sub(pair[0], pair[1])), 0)
	}
}

// spendRecord mirrors ring_policy::SpendRecord::data_hash.
func spendRecord(api frontend.API, address, sender, version, window, commitment frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{SpendRecordDomain, address, sender, version, window, commitment})
}

// countersCommitment mirrors ring_policy::SpendCounters::commitment.
func countersCommitment(api frontend.API, salt frontend.Variable, assets, spent []frontend.Variable) frontend.Variable {
	elements := []frontend.Variable{salt}
	for k := range assets {
		elements = append(elements, assets[k], spent[k])
	}
	return gadget.HashChain(api, elements)
}
