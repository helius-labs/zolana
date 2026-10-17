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

// Select chooses the complete note opening with one Boolean mode selector.
func (w AuditOutputWires) Select(api frontend.API, selected frontend.Variable, other AuditOutputWires) AuditOutputWires {
	return AuditOutputWires{
		Domain:        api.Select(selected, w.Domain, other.Domain),
		TreeID:        api.Select(selected, w.TreeID, other.TreeID),
		OwnerHash:     api.Select(selected, w.OwnerHash, other.OwnerHash),
		Asset:         api.Select(selected, w.Asset, other.Asset),
		Amount:        api.Select(selected, w.Amount, other.Amount),
		Blinding:      api.Select(selected, w.Blinding, other.Blinding),
		DataHash:      api.Select(selected, w.DataHash, other.DataHash),
		RingDataHash:  api.Select(selected, w.RingDataHash, other.RingDataHash),
		RingProgramID: api.Select(selected, w.RingProgramID, other.RingProgramID),
	}
}

// AuditTx is the transaction the caller opened, Hashes commit its output slots.
type AuditTx struct {
	// Compact permits compile-time pruning when the caller pins the shape.
	Compact bool
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
	sealed := Envelope{Plaintext: a.TxViewingSk[:], EphSk: a.EphSk, AuditorPk: a.AuditorPk, Info: auditEncInfo, Compact: tx.Compact}.Seal(api)
	key := gadget.PackBytesBE(api, a.TxViewingSk[:])
	salt := gadget.PackBytesBE(api, a.Salt[:])[0]

	legacy := api.Sub(1, a.Anonymous)
	// A circuit with a fixed ordinary mode need not prove the anonymous
	// serialization or encrypt its longer padding. Witness-controlled modes
	// still execute the complete path.
	mode, constantMode := api.Compiler().ConstantValue(a.Anonymous)
	ordinary := constantMode && mode.Sign() == 0
	chunkCount := auditDisclosureChunks
	if ordinary {
		chunkCount = 1 + 3*chainGroups(AuditOutputSlots*AuditOutputFieldCount)
	}
	plaintext := make([]frontend.Variable, chunkCount)
	for i := range plaintext {
		plaintext[i] = 0
	}
	for i, w := range tx.Outputs {
		active := api.Mul(legacy, tx.NOut.Active[i])
		for f, field := range w.fields() {
			plaintext[i*AuditOutputFieldCount+f] = api.Mul(active, field)
		}
	}
	layout := layout{}
	if !ordinary {
		layout = a.anonymousLayout(api, rc, tx)
	}
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
	if tx.Compact && !ordinary {
		last := 0
		for i, flag := range live {
			if !constantZero(api, flag) {
				last = i + 1
			}
		}
		// Keep the final hash group's zero padding, but no later groups.
		length := 1 + 3*chainGroups(last)
		plaintext, live = plaintext[:length], live[:length]
	}

	// Published fields are the live prefix, the zero tail pads the final HashChain4 group.
	padCount := len(plaintext)
	if ordinary {
		// The last HashChain4 element is a permanent zero. Its pad is unused.
		padCount--
	}
	if tx.Compact {
		for padCount > 1 && constantZero(api, live[padCount-1]) {
			padCount--
		}
	}
	pad := disclosurePad(api, key, salt, padCount)
	states := []frontend.Variable{api.Mul(live[0], api.Add(plaintext[0], pad[0]))}
	for start := 1; start < len(plaintext); start += 3 {
		group := []frontend.Variable{states[len(states)-1]}
		for i := start; i < start+3; i++ {
			if i >= padCount {
				group = append(group, 0)
			} else {
				group = append(group, api.Mul(live[i], api.Add(plaintext[i], pad[i])))
			}
		}
		states = append(states, gadget.PoseidonHash(api, group))
	}
	var disclosure frontend.Variable = 0
	if !tx.Compact || !constantZero(api, legacy) {
		disclosure = api.Mul(legacy, states[chainGroups(AuditOutputSlots*AuditOutputFieldCount)])
	}
	for _, shape := range layout.shapes {
		if tx.Compact && constantZero(api, shape.selected) {
			continue
		}
		disclosure = api.Add(disclosure, api.Mul(shape.selected, states[chainGroups(shape.length)]))
	}

	var outputHash frontend.Variable
	if tx.Compact {
		selectedCount := -1
		for i, selected := range tx.NOut.OneHot {
			value, ok := api.Compiler().ConstantValue(selected)
			if !ok {
				selectedCount = -1
				break
			}
			if value.Sign() != 0 {
				if value.Sign() < 0 || value.BitLen() != 1 || selectedCount != -1 {
					panic("compact audit requires a one-hot output count")
				}
				selectedCount = i + 1
			}
		}
		if selectedCount != -1 {
			outputHash = gadget.HashChain4(api, tx.Hashes[:selectedCount])
		}
	}
	if outputHash == nil {
		outputHash = HashPrefix4(api, tx.Hashes[:], tx.NOut)
	}
	return [12]frontend.Variable{
		a.PrivateTxHash, txPk[0], txPk[1], sealed.Auditor[0], sealed.Auditor[1], sealed.Eph[0], sealed.Eph[1],
		gadget.HashBytes(api, sealed.Ciphertext), outputHash, salt, disclosure, a.Anonymous,
	}
}

func constantZero(api frontend.API, value frontend.Variable) bool {
	v, ok := api.Compiler().ConstantValue(value)
	return ok && v.Sign() == 0
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
