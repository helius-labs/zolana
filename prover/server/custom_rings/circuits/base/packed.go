package base

import (
	"errors"
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. tx_sk is clamped, its tagged public key and the envelope sealing it to the auditor are statement values.
// 2. The output chain covers the first NOut slots, the outputs SPP publishes.
// 3. Every published UTXO is a ring output or an exit, with no data hash under LayoutDataFree.
// 4. A ring output's blinding derives from its CRAS slot secret through CRRC and TXRB, an exit's from SeedOut through TXOB.
// 5. The disclosure opens every published UTXO's owner key, asset and amount, its nullifier key unless LayoutEscrow is set and its data hashes unless LayoutDataFree is set.
// 6. SeedOut opens the disclosure exactly when a published UTXO exits.

// PackedAuditCircuit audits confidential and delegate transfers, their bodies stay unproven.
type PackedAuditCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Capacity        int               `gnark:"-"`
	AuditWires
	NOut      frontend.Variable
	Outputs   []UtxoWires
	OwnerKeys [][32]frontend.Variable
}

// packedRecord is one slot's disclosure fields, zero unless the slot is live.
type packedRecord struct {
	nullifierPk, asset, dataHash, ringDataHash frontend.Variable
	keyAndAmount                               []frontend.Variable
}

func NewPackedAuditCircuit(capacity int) (*PackedAuditCircuit, error) {
	if !slices.Contains(PackedAuditCapacities[:], capacity) {
		return nil, fmt.Errorf("base: unsupported packed audit capacity %d, want one of %v", capacity, PackedAuditCapacities)
	}
	return &PackedAuditCircuit{
		Capacity:  capacity,
		Outputs:   make([]UtxoWires, capacity),
		OwnerKeys: make([][32]frontend.Variable, capacity),
	}, nil
}

func (c *PackedAuditCircuit) Define(api frontend.API) error {
	if err := errors.Join(
		validateLength("output", len(c.Outputs), c.Capacity),
		validateLength("owner key", len(c.OwnerKeys), c.Capacity),
	); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	// 1. The envelope seals tx_sk to the auditor and the layout flags fix the published fields.
	envelope := c.sealEnvelope(api, rc)
	layout := decodeLayout(api, c.Layout, LayoutExits|LayoutEscrow|LayoutDataFree, 0)
	// 2. The count selects the published outputs, the disclosure length ties it to the program's output count.
	nOut := SelectCount(api, c.NOut, 1, c.Capacity)
	hashes := make([]frontend.Variable, c.Capacity)
	slots := make([]outputSlot, c.Capacity)
	records := make([]packedRecord, c.Capacity)
	for i, output := range c.Outputs {
		opened := output.Open(api)
		hashes[i] = opened.Hash
		// 3. Every published UTXO is a ring output or an exit.
		slots[i] = classify(api, output, opened, api.Mul(nOut.Active[i], opened.Utxo))
		live := slots[i].live
		// 4. The ring secret derives from a slot secret only the sender and the auditor hold.
		secret := PackedSlot{TxKey: envelope.key, Salt: envelope.salt, OutputIndex: i, FirstNullifier: c.FirstNullifier}.Secret(api)
		c.assertBlinding(api, output, slots[i], ConfidentialRingSecret(api, secret), i)
		// 5. The disclosed key is the owner the slot hash binds, SolanaOwnerIdentity bounds its bytes.
		assertEqualWhen(api, live, output.OwnerPkHash, gadget.SolanaOwnerIdentity(api, c.OwnerKeys[i]))
		// 6. A data-free disclosure opens no data hash, so no published UTXO carries one.
		dataFree := api.Mul(live, layout.flag(LayoutDataFree))
		assertZeroWhen(api, dataFree, output.DataHash)
		assertZeroWhen(api, dataFree, output.RingDataHash)
		records[i] = newPackedRecord(api, output, c.OwnerKeys[i], live)
	}
	// 7. SeedOut opens the disclosure exactly when an exit needs it.
	layout.assertExits(api, slots)
	statement := c.statement(api, envelope, HashPrefix4(api, hashes, nOut), c.disclosure(api, envelope, layout, nOut, records))
	// 8. The one public input commits the statement the program rebuilds.
	api.AssertIsEqual(c.PublicInputHash, statement)
	return nil
}

func newPackedRecord(api frontend.API, o UtxoWires, ownerKey [32]frontend.Variable, live frontend.Variable) packedRecord {
	return packedRecord{
		nullifierPk:  api.Mul(live, o.NullifierPk),
		asset:        api.Mul(live, o.Asset),
		dataHash:     api.Mul(live, o.DataHash),
		ringDataHash: api.Mul(live, o.RingDataHash),
		keyAndAmount: PackDisclosure(api, slices.Concat(masked(api, live, ownerKey[:]), uintBytes(api, api.Mul(live, o.Amount), 8))),
	}
}

// disclosure is the packed disclosure the layout flags select, mirrored by DisclosureLayout::Packed in custom-rings/interface/src/disclosure.rs.
//
//	SeedOut under LayoutExits, then per published slot nullifier_pk unless LayoutEscrow, asset,
//	data_hash and ring_data_hash unless LayoutDataFree, pack_disclosure(owner_key ‖ u64be(amount))
func (c *PackedAuditCircuit) disclosure(api frontend.API, e auditEnvelope, layout auditLayout, nOut Count, records []packedRecord) frontend.Variable {
	return e.disclose(api, layout.choices(api, LayoutExits|LayoutEscrow|LayoutDataFree), func(choice layoutChoice) disclosureLayout {
		slots := make([][]frontend.Variable, len(records))
		for i, record := range records {
			slots[i] = record.fields(choice)
		}
		return choice.counted(api, c.seedOut(choice), slots, nOut)
	})
}

func (r packedRecord) fields(c layoutChoice) []frontend.Variable {
	var fields []frontend.Variable
	if !c.has(LayoutEscrow) {
		fields = append(fields, r.nullifierPk)
	}
	fields = append(fields, r.asset)
	if !c.has(LayoutDataFree) {
		fields = append(fields, r.dataHash, r.ringDataHash)
	}
	return append(fields, r.keyAndAmount...)
}

// statement is the packed audit preimage, mirrored by AuditStatement::elements under AuditKind::Packed in custom-rings/interface/src/statement.rs.
//
//	head ‖ output_chain, disclosure_chain
func (c *PackedAuditCircuit) statement(api frontend.API, e auditEnvelope, outputChain, disclosureChain frontend.Variable) frontend.Variable {
	return gadget.HashChain4(api, append(e.statementHead(c.AuditWires), outputChain, disclosureChain))
}
