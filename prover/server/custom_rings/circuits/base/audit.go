package base

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/p256"
)

const (
	AuditOutputSlots      = 4
	AuditOutputFieldCount = 9
	// auditEncInfo equals the Rust AUDIT_ENC_INFO.
	auditEncInfo = "CRING/adt1"
	// outputDisclosureDomain is "CR_OD", it separates the disclosure stream.
	outputDisclosureDomain = 0x4352_5f4f44
)

// Audit is the audit witness the base and policy circuits share.
type Audit struct {
	PrivateTxHash frontend.Variable
	TxViewingSk   [32]frontend.Variable
	EphSk         [32]frontend.Variable
	AuditorPk     [65]frontend.Variable
	Salt          [16]frontend.Variable
}

type AuditOutputWires struct {
	Domain        frontend.Variable
	TreeID        frontend.Variable
	OwnerHash     frontend.Variable
	Asset         frontend.Variable
	Amount        frontend.Variable
	Blinding      frontend.Variable
	DataHash      frontend.Variable
	RingDataHash  frontend.Variable
	RingProgramID frontend.Variable
}

func (w AuditOutputWires) Hash(api frontend.API) frontend.Variable {
	return shared.UtxoHashCircuit(api, shared.UtxoCircuitFields{
		Domain: w.Domain, Owner: w.OwnerHash, Asset: w.Asset, Amount: w.Amount, Blinding: w.Blinding,
		DataHash: w.DataHash, RingDataHash: w.RingDataHash, RingProgramID: w.RingProgramID,
	}, w.TreeID)
}

// Define returns the chain elements in CustomRingBasePublicInput order, hashes commit the outputs.
func (a Audit) Define(api frontend.API, rc frontend.Rangechecker, outputs [AuditOutputSlots]AuditOutputWires, hashes [AuditOutputSlots]frontend.Variable, count Count) [11]frontend.Variable {
	CheckBytes(rc, a.TxViewingSk[:], a.Salt[:])
	// The auditor reduces the key mod n, a key at or above n would key the disclosure stream apart.
	p256.AssertScalarInRange(api, a.TxViewingSk)
	tx := p256.CompressPubkey(api, p256.ScalarMulGenerator(api, a.TxViewingSk))
	txPk := gadget.PackBytesBE(api, tx[:])
	sealed := Envelope{Plaintext: a.TxViewingSk[:], EphSk: a.EphSk, AuditorPk: a.AuditorPk, Info: auditEncInfo}.Seal(api, rc)
	key := gadget.PackBytesBE(api, a.TxViewingSk[:])
	salt := gadget.PackBytesBE(api, a.Salt[:])[0]
	disclosure := make([]frontend.Variable, 0, AuditOutputSlots*AuditOutputFieldCount)
	for i, w := range outputs {
		for _, field := range []frontend.Variable{w.Domain, w.TreeID, w.OwnerHash, w.Asset, w.Amount, w.Blinding, w.DataHash, w.RingDataHash, w.RingProgramID} {
			stream := gadget.PoseidonHash(api, []frontend.Variable{outputDisclosureDomain, key[0], key[1], salt, len(disclosure)})
			disclosure = append(disclosure, api.Add(api.Mul(count.Active[i], field), stream))
		}
	}
	return [11]frontend.Variable{
		a.PrivateTxHash, txPk[0], txPk[1], sealed.Auditor[0], sealed.Auditor[1], sealed.Eph[0], sealed.Eph[1],
		gadget.HashBytes(api, sealed.Ciphertext), HashPrefix4(api, hashes[:], count), salt, gadget.HashChain(api, disclosure),
	}
}
