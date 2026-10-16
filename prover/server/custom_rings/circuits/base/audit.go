package base

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/x25519"
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
	AuditorPk     [32]frontend.Variable
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
	CheckBytes(rc, a.Salt[:])
	// The auditor reads the recovered bytes as they are, an unclamped alias would key another stream.
	AssertClamped(api, a.TxViewingSk)
	txPk := gadget.PackBytesBE(api, TaggedPubkey(api, a.TxViewingSk))
	sealed := Envelope{Plaintext: a.TxViewingSk[:], EphSk: a.EphSk, AuditorPk: a.AuditorPk, Info: auditEncInfo}.Seal(api)
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

// AssertClamped pins the RFC 7748 clamped encoding, the one byte string per X25519 key.
func AssertClamped(api frontend.API, secret [32]frontend.Variable) {
	low := api.ToBinary(secret[0], 8)
	high := api.ToBinary(secret[31], 8)
	for _, bit := range low[:3] {
		api.AssertIsEqual(bit, 0)
	}
	api.AssertIsEqual(high[6], 1)
	api.AssertIsEqual(high[7], 0)
}

// TaggedPubkey is 0x04 || u of the clamped secret, the generator gadget bounds every secret byte.
func TaggedPubkey(api frontend.API, secret [32]frontend.Variable) []frontend.Variable {
	u := x25519.ScalarMulGenerator(api, secret)
	return append([]frontend.Variable{4}, u[:]...)
}
