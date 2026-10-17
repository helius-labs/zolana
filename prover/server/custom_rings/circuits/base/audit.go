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
	// AuditInputSlots bounds the inputs an anonymous ring discloses.
	AuditInputSlots = 4
	// IdentityLen is an owner tag and its 32 key bytes, HashBytes of it is the owner pk hash.
	IdentityLen = 33
	// auditEncInfo equals the Rust AUDIT_ENC_INFO.
	auditEncInfo = "CRING/adt1"
	// outputDisclosureDomain is "CR_OD", it separates the disclosure stream.
	outputDisclosureDomain = 0x4352_5f4f44
)

// Audit is the audit witness the base and policy circuits share.
type Audit struct {
	PrivateTxHash frontend.Variable
	// Anonymous discloses the hidden sender, the spent notes and every recipient.
	Anonymous   frontend.Variable
	TxViewingSk [32]frontend.Variable
	EphSk       [32]frontend.Variable
	AuditorPk   [32]frontend.Variable
	Salt        [16]frontend.Variable
	// Only an anonymous ring reads the identities and viewing keys, a legacy sender is zero.
	Sender               [IdentityLen]frontend.Variable
	Recipients           [AuditOutputSlots][IdentityLen]frontend.Variable
	RecipientViewingKeys [AuditOutputSlots][33]frontend.Variable
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

func (w AuditOutputWires) fields() [AuditOutputFieldCount]frontend.Variable {
	return [AuditOutputFieldCount]frontend.Variable{
		w.Domain, w.TreeID, w.OwnerHash, w.Asset, w.Amount, w.Blinding, w.DataHash, w.RingDataHash, w.RingProgramID,
	}
}

// AuditTx is the transaction the caller opened, Hashes commit its output slots.
type AuditTx struct {
	Outputs [AuditOutputSlots]AuditOutputWires
	Hashes  [AuditOutputSlots]frontend.Variable
	NOut    Count
	// NIn.OneHot[k] selects k+1 disclosed inputs, the caller pins one in an anonymous ring.
	NIn    Count
	Inputs [AuditInputSlots]AuditUtxoWires
	Notes  [AuditOutputSlots]AuditUtxoWires
}

// Define returns the chain elements in CustomRingBasePublicInput order.
func (a Audit) Define(api frontend.API, rc frontend.Rangechecker, tx AuditTx) [12]frontend.Variable {
	api.AssertIsBoolean(a.Anonymous)
	CheckBytes(rc, a.Salt[:])
	// The auditor reads the recovered bytes as they are, an unclamped alias would key another stream.
	AssertClamped(api, a.TxViewingSk)
	txPk := gadget.PackBytesBE(api, TaggedPubkey(api, a.TxViewingSk))
	sealed := Envelope{Plaintext: a.TxViewingSk[:], EphSk: a.EphSk, AuditorPk: a.AuditorPk, Info: auditEncInfo}.Seal(api)
	key := gadget.PackBytesBE(api, a.TxViewingSk[:])
	salt := gadget.PackBytesBE(api, a.Salt[:])[0]

	legacy := api.Sub(1, a.Anonymous)
	plaintext := make([]frontend.Variable, auditDisclosureChunks)
	for i := range plaintext {
		plaintext[i] = 0
	}
	for i, w := range tx.Outputs {
		active := api.Mul(legacy, tx.NOut.Active[i])
		for f, field := range w.fields() {
			plaintext[i*AuditOutputFieldCount+f] = api.Mul(active, field)
		}
	}
	layout := a.anonymousLayout(api, rc, tx)
	for i, chunk := range layout.chunks {
		plaintext[i] = api.Add(plaintext[i], chunk)
	}
	live := make([]frontend.Variable, len(plaintext))
	for i := range live {
		live[i] = 0
		if i < AuditOutputSlots*AuditOutputFieldCount {
			live[i] = legacy
		}
		for _, shape := range layout.shapes {
			if i < shape.length {
				live[i] = api.Add(live[i], shape.selected)
			}
		}
	}

	// Published fields are the live prefix, the zero tail pads the final HashChain4 group.
	pad := disclosurePad(api, key, salt, len(plaintext))
	states := []frontend.Variable{api.Mul(live[0], api.Add(plaintext[0], pad[0]))}
	for start := 1; start < len(plaintext); start += 3 {
		group := []frontend.Variable{states[len(states)-1]}
		for i := start; i < start+3; i++ {
			group = append(group, api.Mul(live[i], api.Add(plaintext[i], pad[i])))
		}
		states = append(states, gadget.PoseidonHash(api, group))
	}
	disclosure := api.Mul(legacy, states[chainGroups(AuditOutputSlots*AuditOutputFieldCount)])
	for _, shape := range layout.shapes {
		disclosure = api.Add(disclosure, api.Mul(shape.selected, states[chainGroups(shape.length)]))
	}

	return [12]frontend.Variable{
		a.PrivateTxHash, txPk[0], txPk[1], sealed.Auditor[0], sealed.Auditor[1], sealed.Eph[0], sealed.Eph[1],
		gadget.HashBytes(api, sealed.Ciphertext), HashPrefix4(api, tx.Hashes[:], tx.NOut), salt, disclosure, a.Anonymous,
	}
}

// chainGroups is the HashChain4 state index that absorbs the first n values.
func chainGroups(n int) int {
	return (n - 1 + 2) / 3
}

// disclosurePad iterates a two-input Poseidon from the keyed seed, pad[i] is the state after step i.
func disclosurePad(api frontend.API, key []frontend.Variable, salt frontend.Variable, n int) []frontend.Variable {
	state := gadget.PoseidonHash(api, []frontend.Variable{outputDisclosureDomain, key[0], key[1], salt})
	pad := make([]frontend.Variable, n)
	for i := range pad {
		state = gadget.PoseidonHash(api, []frontend.Variable{state, i})
		pad[i] = state
	}
	return pad
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
