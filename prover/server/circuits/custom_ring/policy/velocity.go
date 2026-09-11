// Bounds one sender's outflow per mint over a fixed window through a spend
// record spent into its successor, and raises the dual control bit.

package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
)

// VelocityRowWires is one committed spend window row, a zero cap or threshold
// leaves that bound off.
type VelocityRowWires struct {
	Asset       frontend.Variable
	Cap         frontend.Variable
	CosignAbove frontend.Variable
}

// RecordWires opens the sender's latest spend record and names the salt of
// its successor.
type RecordWires struct {
	Version frontend.Variable
	Window  frontend.Variable
	// The published counters commitment, opened only inside the current window.
	Commitment frontend.Variable
	Salt       frontend.Variable
	Assets     [NVelocityAssets]frontend.Variable
	Spent      [NVelocityAssets]frontend.Variable
	// The successor commits under a fresh salt.
	NextSalt frontend.Variable
}

// velocityPolicy supplies the checked window switch and row flags.
type velocityPolicy struct {
	on      frontend.Variable
	enabled [NVelocityAssets]frontend.Variable
}

// checkVelocityTable binds the rows to the window switch and rejects
// unusable rows.
func (c *CustomRingPolicyCircuit) checkVelocityTable(api frontend.API, rangeChecker frontend.Rangechecker) velocityPolicy {
	// 1. Select the committed row prefix, rows and a window come together.
	assertOneHot(api, c.VelocityCountSelected[:])
	inTable := suffixSums(api, c.VelocityCountSelected[:])
	var enabled [NVelocityAssets]frontend.Variable
	copy(enabled[:], inTable[1:])
	rangeChecker.Check(c.WindowSlots, amountBits)
	off := api.IsZero(c.WindowSlots)
	api.AssertIsEqual(off, c.VelocityCountSelected[0])

	// 2. Bound every row, require a mint and a bound, exclude nonzero padding
	// and repeated mints.
	for i, row := range c.Velocity {
		rangeChecker.Check(row.Cap, amountBits)
		rangeChecker.Check(row.CosignAbove, amountBits)
		shared.AssertWhen(api, enabled[i], nonZero(api, row.Asset))
		shared.AssertWhen(api, enabled[i], nonZero(api, api.Add(row.Cap, row.CosignAbove)))
		padding := api.Sub(1, enabled[i])
		api.AssertIsEqual(api.Mul(padding, row.Asset), 0)
		api.AssertIsEqual(api.Mul(padding, row.Cap), 0)
		api.AssertIsEqual(api.Mul(padding, row.CosignAbove), 0)
		for j := 0; j < i; j++ {
			shared.AssertWhen(api, api.Mul(enabled[i], enabled[j]), nonZero(api, api.Sub(row.Asset, c.Velocity[j].Asset)))
		}
	}
	return velocityPolicy{on: api.Sub(1, off), enabled: enabled}
}

// constrainVelocity pins the record slots, charges the sender's outflow per
// row to its successor record and raises the dual control bit.
func (c *CustomRingPolicyCircuit) constrainVelocity(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	policy velocityPolicy,
	txContext transactionContext,
) {
	// 1. Money rides beside the record, the first input names the one
	// sender.
	api.AssertIsEqual(txContext.inputs[0].record, 0)
	shared.AssertWhen(api, policy.on, txContext.inputs[0].live)
	sender := txContext.inputs[0].ownerPkHash
	for _, input := range txContext.inputs[1:] {
		shared.AssertWhen(api, api.Mul(policy.on, input.live), api.IsZero(api.Sub(input.ownerPkHash, sender)))
	}

	// 2. No slot outside the record opens to the namespace.
	for _, slot := range append(txContext.inputs[:], txContext.outputs[:]...) {
		shared.AssertWhen(api, api.Mul(slot.active, api.Sub(1, slot.record)), nonZero(api, api.Sub(slot.owner, c.NamespaceOwnerHash)))
	}

	// 3. Open the record at the sender's address, a record from a future
	// window is refused.
	rangeChecker.Check(c.Record.Version, amountBits)
	rangeChecker.Check(c.Record.Window, amountBits)
	rangeChecker.Check(c.WindowIndex, amountBits)
	shared.AssertWhen(api, policy.on, outputTotalAtMost(api, c.Record.Window, c.WindowIndex))
	shared.AssertWhen(api, api.Sub(1, policy.on), api.IsZero(c.WindowIndex))
	sameWindow := api.IsZero(api.Sub(c.Record.Window, c.WindowIndex))
	address := spendAddress(api, c.NamespaceOwnerHash, sender, c.EntriesTreeID)
	spentDataHash := recordDataHash(api, address, sender, c.Record.Version, c.Record.Window, c.Record.Commitment)
	for i, slot := range c.Inputs {
		slot.assertRecord(api, txContext.inputs[i], c.NamespaceOwnerHash, c.EntriesTreeID, spentDataHash)
	}

	// 4. Open the counters inside the window, an expired record needs only
	// its published commitment.
	for k := range c.Record.Spent {
		rangeChecker.Check(c.Record.Spent[k], amountBits)
	}
	opened := countersCommitment(api, c.Record.Salt, c.Record.Assets[:], c.Record.Spent[:])
	api.AssertIsEqual(api.Mul(policy.on, sameWindow, api.Sub(opened, c.Record.Commitment)), 0)

	// 5. Charge each row's outflow, previous counters count only inside the
	// window.
	approval := frontend.Variable(0)
	var nextAssets, nextSpent [NVelocityAssets]frontend.Variable
	for r, row := range c.Velocity {
		inflow := frontend.Variable(0)
		for _, input := range txContext.inputs {
			inflow = api.Add(inflow, api.Mul(input.live, api.IsZero(api.Sub(input.asset, row.Asset)), input.amount))
		}
		change := frontend.Variable(0)
		for _, output := range txContext.outputs {
			toSender := api.Mul(api.IsZero(api.Sub(output.ownerPkHash, sender)), api.IsZero(api.Sub(output.ringProgramID, c.RingID)))
			change = api.Add(change, api.Mul(output.live, api.IsZero(api.Sub(output.asset, row.Asset)), toSender, output.amount))
		}
		shared.AssertWhen(api, policy.enabled[r], outputTotalAtMost(api, change, inflow))
		outflow := api.Sub(inflow, change)

		previous := frontend.Variable(0)
		for k := range c.Record.Assets {
			previous = api.Add(previous, api.Mul(api.IsZero(api.Sub(c.Record.Assets[k], row.Asset)), c.Record.Spent[k]))
		}
		spent := api.Mul(policy.enabled[r], api.Add(api.Mul(sameWindow, previous), outflow))
		rangeChecker.Check(spent, amountBits)
		capped := api.Mul(policy.enabled[r], nonZero(api, row.Cap))
		shared.AssertWhen(api, capped, outputTotalAtMost(api, spent, row.Cap))
		cosigned := api.Mul(policy.enabled[r], nonZero(api, row.CosignAbove))
		approval = api.Or(approval, api.Mul(cosigned, api.Sub(1, outputTotalAtMost(api, outflow, row.CosignAbove))))

		nextAssets[r] = row.Asset
		nextSpent[r] = spent
	}
	api.AssertIsBoolean(c.ApprovalRequired)
	api.AssertIsEqual(c.ApprovalRequired, approval)

	// 6. Pin the successor at the next version under the current window.
	nextCommitment := countersCommitment(api, c.Record.NextSalt, nextAssets[:], nextSpent[:])
	nextDataHash := recordDataHash(api, address, sender, api.Add(c.Record.Version, 1), c.WindowIndex, nextCommitment)
	for i, slot := range c.Outputs {
		slot.assertRecord(api, txContext.outputs[i], c.NamespaceOwnerHash, c.EntriesTreeID, nextDataHash)
	}
}

// assertRecord requires a record slot to be the namespace's zero-amount SOL
// leaf under the entries tree with the expected data hash.
func (w UtxoWires) assertRecord(api frontend.API, view utxoView, namespaceOwnerHash, entriesTreeID, dataHash frontend.Variable) {
	for _, pair := range [][2]frontend.Variable{
		{w.Domain, shared.UtxoDomain},
		{view.owner, namespaceOwnerHash},
		{w.TreeID, entriesTreeID},
		{w.Asset, solAssetField},
		{w.Amount, 0},
		{w.RingDataHash, 0},
		{w.RingProgramID, 0},
		{w.DataHash, dataHash},
	} {
		api.AssertIsEqual(api.Mul(view.record, api.Sub(pair[0], pair[1])), 0)
	}
}

// spendAddress derives the sender's record address under the namespace.
func spendAddress(api frontend.API, namespaceOwnerHash, sender, treeID frontend.Variable) frontend.Variable {
	seed := gadget.PoseidonHash(api, []frontend.Variable{spendAddressDomain, sender})
	return gadget.PoseidonHash(api, []frontend.Variable{addressUtxoHash(api, namespaceOwnerHash, seed, treeID), seed, 0})
}

// recordDataHash mirrors ring_policy::SpendRecord::data_hash.
func recordDataHash(api frontend.API, address, sender, version, window, commitment frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{spendRecordDomain, address, sender, version, window, commitment})
}

// countersCommitment mirrors ring_policy::SpendCounters::commitment.
func countersCommitment(api frontend.API, salt frontend.Variable, assets, spent []frontend.Variable) frontend.Variable {
	elements := make([]frontend.Variable, 0, 1+2*len(assets))
	elements = append(elements, salt)
	for k := range assets {
		elements = append(elements, assets[k], spent[k])
	}
	return gadget.HashChain(api, elements)
}
