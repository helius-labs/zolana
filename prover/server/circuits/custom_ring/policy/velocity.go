package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
)

// Caps one asset's outflow and selects amount-based co-signing.
type VelocityRowWires struct {
	Asset       frontend.Variable
	Cap         frontend.Variable
	CosignAbove frontend.Variable
}

// Opens predecessor counters for the successor's spend record.
type RecordWires struct {
	Version frontend.Variable
	Window  frontend.Variable
	// The published counters commitment, opened only inside the current window.
	Commitment frontend.Variable
	Salt       frontend.Variable
	Assets     [NVelocityAssets]frontend.Variable
	Spent      [NVelocityAssets]frontend.Variable
	// Must be fresh for each successor.
	NextSalt frontend.Variable
}

type velocityPolicy struct {
	windowEnabled frontend.Variable
	rowsEnabled   frontend.Variable
	rowEnabled    [NVelocityAssets]frontend.Variable
}

type recordExpectation struct {
	owner    frontend.Variable
	treeID   frontend.Variable
	dataHash frontend.Variable
}

type spendRecordFields struct {
	address    frontend.Variable
	sender     frontend.Variable
	version    frontend.Variable
	window     frontend.Variable
	commitment frontend.Variable
}

// A fixed window requires at least one enabled accounting row.
func (c *CustomRingPolicyCircuit) checkVelocityTable(api frontend.API, rangeChecker frontend.Rangechecker) velocityPolicy {
	assertOneHot(api, c.VelocityCountSelected[:])
	inTable := suffixSums(api, c.VelocityCountSelected[:])
	var enabled [NVelocityAssets]frontend.Variable
	copy(enabled[:], inTable[1:])
	rangeChecker.Check(c.WindowSlots, amountBits)
	off := api.IsZero(c.WindowSlots)
	api.AssertIsEqual(api.Mul(api.Sub(1, off), c.VelocityCountSelected[0]), 0)

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
	return velocityPolicy{windowEnabled: api.Sub(1, off), rowsEnabled: api.Sub(1, c.VelocityCountSelected[0]), rowEnabled: enabled}
}

// Outflow excludes only change returned to the same sender inside the ring.
func (c *CustomRingPolicyCircuit) constrainVelocity(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	policy velocityPolicy,
	txContext transactionContext,
) {
	// 1. Require all money inputs to share one owner.
	api.AssertIsEqual(txContext.inputs[0].record, 0)
	shared.AssertWhen(api, policy.rowsEnabled, txContext.inputs[0].live)
	sender := txContext.inputs[0].ownerPkHash
	for _, input := range txContext.inputs[1:] {
		shared.AssertWhen(api, api.Mul(policy.rowsEnabled, input.live), api.IsZero(api.Sub(input.ownerPkHash, sender)))
	}
	// Windowed spends must not use the namespace to claim addresses.
	var noAddresses [NInputs]frontend.Variable
	for i := range noAddresses {
		noAddresses[i] = 0
	}
	emptyAddressChain := hashPrefix4(api, noAddresses[:], c.InputCountSelected[:])
	api.AssertIsEqual(api.Mul(policy.windowEnabled, api.Sub(c.AddressChain, emptyAddressChain)), 0)

	// 2. Authenticate the record and open counters for its current window.
	rangeChecker.Check(c.Record.Version, amountBits)
	rangeChecker.Check(c.Record.Window, amountBits)
	rangeChecker.Check(c.WindowIndex, amountBits)
	shared.AssertWhen(api, policy.windowEnabled, outputTotalAtMost(api, c.Record.Window, c.WindowIndex))
	shared.AssertWhen(api, api.Sub(1, policy.windowEnabled), api.IsZero(c.WindowIndex))
	sameWindow := api.IsZero(api.Sub(c.Record.Window, c.WindowIndex))
	address := spendAddress(api, c.NamespaceOwnerHash, sender, c.EntriesTreeID)
	spent := recordExpectation{
		owner:  c.NamespaceOwnerHash,
		treeID: c.EntriesTreeID,
		dataHash: spendRecordFields{
			address:    address,
			sender:     sender,
			version:    c.Record.Version,
			window:     c.Record.Window,
			commitment: c.Record.Commitment,
		}.dataHash(api),
	}
	for i, slot := range c.Inputs {
		slot.assertRecord(api, txContext.inputs[i], spent)
	}

	for k := range c.Record.Spent {
		rangeChecker.Check(c.Record.Spent[k], amountBits)
	}
	opened := countersCommitment(api, c.Record.Salt, c.Record.Assets[:], c.Record.Spent[:])
	api.AssertIsEqual(api.Mul(policy.windowEnabled, sameWindow, api.Sub(opened, c.Record.Commitment)), 0)

	// 3. Bound cumulative spending before applying per-mint caps.
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
		shared.AssertWhen(api, policy.rowEnabled[r], outputTotalAtMost(api, change, inflow))
		outflow := api.Sub(inflow, change)

		previous := frontend.Variable(0)
		for k := range c.Record.Assets {
			previous = api.Add(previous, api.Mul(api.IsZero(api.Sub(c.Record.Assets[k], row.Asset)), c.Record.Spent[k]))
		}
		spent := api.Mul(policy.rowEnabled[r], api.Add(api.Mul(policy.windowEnabled, sameWindow, previous), outflow))
		rangeChecker.Check(spent, amountBits)
		capped := api.Mul(policy.rowEnabled[r], nonZero(api, row.Cap))
		shared.AssertWhen(api, capped, outputTotalAtMost(api, spent, row.Cap))
		cosigned := api.Mul(policy.rowEnabled[r], nonZero(api, row.CosignAbove))
		approval = api.Or(approval, api.Mul(cosigned, api.Sub(1, outputTotalAtMost(api, outflow, row.CosignAbove))))

		nextAssets[r] = row.Asset
		nextSpent[r] = spent
	}
	// 4. Require approval when an enabled co-sign threshold is exceeded.
	api.AssertIsBoolean(c.ApprovalRequired)
	api.AssertIsEqual(c.ApprovalRequired, approval)

	// 5. Bind the successor's u64 version and counters to its output.
	nextVersion := api.Add(c.Record.Version, 1)
	rangeChecker.Check(api.Mul(policy.windowEnabled, nextVersion), amountBits)
	nextCommitment := countersCommitment(api, c.Record.NextSalt, nextAssets[:], nextSpent[:])
	successor := recordExpectation{
		owner:  c.NamespaceOwnerHash,
		treeID: c.EntriesTreeID,
		dataHash: spendRecordFields{
			address:    address,
			sender:     sender,
			version:    nextVersion,
			window:     c.WindowIndex,
			commitment: nextCommitment,
		}.dataHash(api),
	}
	for i, slot := range c.Outputs {
		slot.assertRecord(api, txContext.outputs[i], successor)
	}
}

// Only the member record pair may use the namespace owner.
func (c *CustomRingPolicyCircuit) constrainNamespace(api frontend.API, txContext transactionContext) {
	for _, slot := range append(txContext.inputs[:], txContext.outputs[:]...) {
		shared.AssertWhen(api, api.Mul(slot.active, api.Sub(1, slot.record)), nonZero(api, api.Sub(slot.owner, c.NamespaceOwnerHash)))
	}
}

func (w UtxoWires) assertRecord(api frontend.API, view utxoView, want recordExpectation) {
	for _, pair := range [][2]frontend.Variable{
		{w.Domain, shared.UtxoDomain},
		{view.owner, want.owner},
		{w.TreeID, want.treeID},
		{w.Asset, solAssetField},
		{w.Amount, 0},
		{w.RingDataHash, 0},
		{w.RingProgramID, 0},
		{w.DataHash, want.dataHash},
	} {
		api.AssertIsEqual(api.Mul(view.record, api.Sub(pair[0], pair[1])), 0)
	}
}

// Mirrors ring_policy::ListNamespace::spend_address.
func spendAddress(api frontend.API, namespaceOwnerHash, sender, treeID frontend.Variable) frontend.Variable {
	seed := gadget.PoseidonHash(api, []frontend.Variable{SpendAddressDomain, sender})
	return gadget.PoseidonHash(api, []frontend.Variable{addressUtxoHash(api, namespaceOwnerHash, seed, treeID), seed, 0})
}

// Mirrors ring_policy::SpendRecord::data_hash.
func (r spendRecordFields) dataHash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{SpendRecordDomain, r.address, r.sender, r.version, r.window, r.commitment})
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
