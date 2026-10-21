package base_test

import (
	"encoding/hex"
	"math/big"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	base "github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Every published anonymous slot carries one 105-byte scheme-9 body, random in a padding slot, and the statement binds both.

const recipientVectorPath = "../../../../../test-vectors/anonymous_recipient_encryption.json"

const recipientVectorDescription = "Known-answer vector for the anonymous ring recipient encryption. " +
	"tx_sk is the clamped transaction viewing secret and tx_pk its tagged key 0x04 || u, recipient_viewing_sk is the recipient's " +
	"X25519 scalar and recipient_viewing_pk its tagged key. dh = X25519(tx_sk, recipient_viewing_pk.u). " +
	"secret = Poseidon(0x4352_5f52, dh_lo, dh_hi, tx_pk_lo, tx_pk_hi, recipient_pk_lo, recipient_pk_hi, salt_field, slot) with " +
	"lo = the first 31 bytes and hi = the rest of PackBytesBE, salt_field the 16 salt bytes right aligned and slot the output index. " +
	"key and nonce are the audit stream schedule of secret, the same as the auditor envelope, and ciphertext = AES-256-CTR(key, nonce, plaintext) " +
	"from counter block nonce || 0x00000002. plaintext = asset_address(32) || amount u64 big-endian || blinding(32) canonical || pair_u(32). " +
	"body = 0x09 || ciphertext and body_hash = hash_bytes(body). statement is the 2x2 base statement with one real ring output in slot 0 and one " +
	"padding slot whose body is padding_body, output_body_hashes[i] = hash_bytes of each body, elements is the 13-element base chain in order " +
	"with the body chain after the auditor ciphertext hash, and public_input_hash = hash_chain(elements). policy_statement extends those " +
	"13 elements with the policy tail in CustomRingPolicyPublicInput order, policy_hash, the tree slots hash chain, address_tree_id as a field, " +
	"ring_id = hash_bytes(ring_program_id), namespace_owner_hash, approval_required, key_escrow, member_registry_root, foreign_root, and " +
	"public_input_hash = hash_chain(elements) over its 22 elements. All values are hex. " +
	"Produced by prover/server/custom_rings/circuits/base/recipient_test.go with WRITE_AUDIT_VECTORS=1."

type recipientVector struct {
	Description        string `json:"description"`
	TxSk               string `json:"tx_sk"`
	TxPk               string `json:"tx_pk"`
	RecipientViewingSk string `json:"recipient_viewing_sk"`
	RecipientViewingPk string `json:"recipient_viewing_pk"`
	SigningIdentity    string `json:"signing_identity"`
	NullifierPk        string `json:"nullifier_pk"`
	RingProgramID      string `json:"ring_program_id"`
	Salt               string `json:"salt"`
	Slot               int    `json:"slot"`
	AssetAddress       string `json:"asset_address"`
	Amount             uint64 `json:"amount"`
	Blinding           string `json:"blinding"`
	PairU              string `json:"pair_u"`
	Dh                 string `json:"dh"`
	Secret             string `json:"secret"`
	Key                string `json:"key"`
	Nonce              string `json:"nonce"`
	Plaintext          string `json:"plaintext"`
	Ciphertext         string `json:"ciphertext"`
	Body               string `json:"body"`
	BodyHash           string `json:"body_hash"`

	Statement       recipientStatementVector       `json:"statement"`
	PolicyStatement recipientPolicyStatementVector `json:"policy_statement"`
}

type recipientPolicyStatementVector struct {
	PolicyHash         string           `json:"policy_hash"`
	TreeSlots          []vectorTreeSlot `json:"tree_slots"`
	AddressTreeID      uint16           `json:"address_tree_id"`
	RingID             string           `json:"ring_id"`
	NamespaceOwnerHash string           `json:"namespace_owner_hash"`
	ApprovalRequired   bool             `json:"approval_required"`
	KeyEscrow          bool             `json:"key_escrow"`
	MemberRegistryRoot string           `json:"member_registry_root"`
	ForeignRoot        string           `json:"foreign_root"`
	Elements           []string         `json:"elements"`
	PublicInputHash    string           `json:"public_input_hash"`
}

type vectorTreeSlot struct {
	ID            uint16 `json:"id"`
	UtxoRoot      string `json:"utxo_root"`
	NullifierRoot string `json:"nullifier_root"`
}

// policyStatement appends a synthetic policy tail to the base statement, as the policy circuits chain it.
func policyStatement(t *testing.T, s ringaudit.Statement, elements []*big.Int) recipientPolicyStatementVector {
	t.Helper()
	const addressTreeID = 7
	slot := protocol.TreeSlot{ID: big.NewInt(addressTreeID), UtxoRoot: big.NewInt(0x1234), NullifierRoot: big.NewInt(0x5678)}
	slots, err := protocol.PadTreeSlots(slot)
	if err != nil {
		t.Fatal(err)
	}
	policyHash, namespaceOwner, membersRoot, foreignRoot := big.NewInt(0xa1), big.NewInt(0xa2), big.NewInt(0xa3), big.NewInt(0)
	ringID := spptest.AsBigInt(s.Notes[0].RingProgramID)
	tail := []*big.Int{
		policyHash, spptest.MustTreeSlotsHashChain(t, slots), big.NewInt(addressTreeID),
		ringID, namespaceOwner, big.NewInt(0), big.NewInt(1), membersRoot, foreignRoot,
	}
	chain := append(append([]*big.Int{}, elements...), tail...)
	field := func(value *big.Int) string { return hexFields(t, []*big.Int{value})[0] }
	return recipientPolicyStatementVector{
		PolicyHash:         field(policyHash),
		TreeSlots:          []vectorTreeSlot{{ID: addressTreeID, UtxoRoot: field(slot.UtxoRoot), NullifierRoot: field(slot.NullifierRoot)}},
		AddressTreeID:      addressTreeID,
		RingID:             field(ringID),
		NamespaceOwnerHash: field(namespaceOwner),
		ApprovalRequired:   false,
		KeyEscrow:          true,
		MemberRegistryRoot: field(membersRoot),
		ForeignRoot:        field(foreignRoot),
		Elements:           hexFields(t, chain),
		PublicInputHash:    field(spptest.MustHashChain(t, chain)),
	}
}

type recipientStatementVector struct {
	NIn              int      `json:"n_in"`
	NOut             int      `json:"n_out"`
	PrivateTxHash    string   `json:"private_tx_hash"`
	TxViewingPk      string   `json:"tx_viewing_pk"`
	AuditorPk        string   `json:"auditor_pk"`
	EphPk            string   `json:"eph_pk"`
	AuditCiphertext  string   `json:"audit_ciphertext"`
	OutputHashes     []string `json:"output_hashes"`
	PaddingBody      string   `json:"padding_body"`
	OutputBodyHashes []string `json:"output_body_hashes"`
	Salt             string   `json:"salt"`
	Disclosure       []string `json:"disclosure"`
	Anonymous        bool     `json:"anonymous"`
	Elements         []string `json:"elements"`
	PublicInputHash  string   `json:"public_input_hash"`
}

const recipientScalarSeed = 0x55

// twoByTwo spends one note and a dummy into one ring note and one padding slot under the vector key and salt.
func twoByTwo(t *testing.T) (ringaudit.Keys, ringaudit.Statement) {
	t.Helper()
	key, salt := vectorKey()
	keys := ringaudit.DefaultKeys(t).WithTxScalar(t, key)
	s := keys.AnonymousStatement(t)
	for i, b := range salt {
		s.Audit.Salt[i] = int(b)
	}
	s.NIn, s.Count = 2, 2
	s.Inputs[1].Domain = big.NewInt(protocol.DummyDomain)
	s.Notes[1].Domain = big.NewInt(protocol.DummyDomain)
	s.Notes[1].Blinding = big.NewInt(0x7a)
	for i := range s.Deliveries[1].Ciphertext {
		s.Deliveries[1].Ciphertext[i] = byte(0xd0 + i)
	}
	keys.Deliver(t, &s)
	return keys, s
}

func TestRecipientEncryptionVectorPinsHostAndCircuit(t *testing.T) {
	keys, s := twoByTwo(t)
	viewing := [33]byte(ringaudit.Tagged(ringaudit.XPrivateKey(t, ringaudit.Scalar(recipientScalarSeed)).PublicKey().Bytes()))
	stream := keys.RecipientStream(t, viewing, s.Salt(), 0)
	plaintext := ringaudit.OutputPlaintext(s, 0)
	ciphertext := s.Deliveries[0].Ciphertext
	if keys.SealOutput(t, s, 0, 0, plaintext) != ciphertext {
		t.Fatal("the delivered body is not the stream encryption of the opening")
	}
	body := ringaudit.Body(ciphertext)
	padding := ringaudit.Body(s.Deliveries[1].Ciphertext)
	elements := keys.BaseChainElementsFor(t, s)
	secret := ringaudit.Scalar(recipientScalarSeed)
	txSk, salt := keys.TxSk(), s.Salt()
	bodyHashes := ringaudit.BodyHashes(t, s)
	want := recipientVector{
		Description:        recipientVectorDescription,
		TxSk:               hex.EncodeToString(txSk[:]),
		TxPk:               hexElements(t, elements[1:3]),
		RecipientViewingSk: hex.EncodeToString(secret[:]),
		RecipientViewingPk: hex.EncodeToString(viewing[:]),
		SigningIdentity:    hex.EncodeToString(bytesOf(s.Audit.Recipients[0][:])),
		NullifierPk:        hexFields(t, []*big.Int{spptest.AsBigInt(s.Notes[0].NullifierPk)})[0],
		RingProgramID:      hex.EncodeToString(s.RingProgramID[:]),
		Salt:               hex.EncodeToString(salt[:]),
		Slot:               0,
		AssetAddress:       hex.EncodeToString(s.Deliveries[0].AssetAddress[:]),
		Amount:             spptest.AsBigInt(s.Notes[0].Amount).Uint64(),
		Blinding:           hexFields(t, []*big.Int{spptest.AsBigInt(s.Notes[0].Blinding)})[0],
		PairU:              hex.EncodeToString(s.Deliveries[0].PairU[:]),
		Dh:                 hex.EncodeToString(stream.Dh[:]),
		Secret:             hexFields(t, []*big.Int{stream.Secret})[0],
		Key:                hex.EncodeToString(stream.Key[:]),
		Nonce:              hex.EncodeToString(stream.Nonce[:]),
		Plaintext:          hex.EncodeToString(plaintext[:]),
		Ciphertext:         hex.EncodeToString(ciphertext[:]),
		Body:               hex.EncodeToString(body[:]),
		BodyHash:           hexFields(t, bodyHashes[:1])[0],
		Statement: recipientStatementVector{
			NIn: s.NIn, NOut: s.Count,
			PrivateTxHash:    hexFields(t, []*big.Int{spptest.AsBigInt(s.Audit.PrivateTxHash)})[0],
			TxViewingPk:      hexElements(t, elements[1:3]),
			AuditorPk:        hexElements(t, elements[3:5]),
			EphPk:            hexElements(t, elements[5:7]),
			AuditCiphertext:  hex.EncodeToString(keys.EnvelopeCiphertext(t, txSk[:], "CRING/adt1")),
			OutputHashes:     hexFields(t, outputHashes(t, s)),
			PaddingBody:      hex.EncodeToString(padding[:]),
			OutputBodyHashes: hexFields(t, bodyHashes),
			Salt:             hex.EncodeToString(salt[:]),
			Disclosure:       hexFields(t, disclosureFields(t, keys, s)),
			Anonymous:        true,
			Elements:         hexFields(t, elements),
			PublicInputHash:  hexFields(t, []*big.Int{spptest.MustHashChain(t, elements)})[0],
		},
		PolicyStatement: policyStatement(t, s, elements),
	}
	if txPk := keys.TxPk(); want.TxPk != hex.EncodeToString(txPk[:]) {
		t.Fatal("the packed viewing key does not unpack to the tagged key")
	}
	var got recipientVector
	readVector(t, recipientVectorPath, want, &got)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("the host mirror disagrees with test-vectors/anonymous_recipient_encryption.json, rewrite it with WRITE_AUDIT_VECTORS=1")
	}
	pinned, err := hex.DecodeString(got.Statement.PublicInputHash)
	if err != nil {
		t.Fatal(err)
	}
	circuit := keys.Circuit(t, s)
	circuit.PublicInputHash = new(big.Int).SetBytes(pinned)
	solve(t, testConstraintSystem(t), circuit)
}

// hexElements unpacks a lo, hi field pair back into the 33 tagged key bytes.
func hexElements(t *testing.T, pair []*big.Int) string {
	t.Helper()
	lo, hi := spptest.MustFieldBytes(t, pair[0]), spptest.MustFieldBytes(t, pair[1])
	return hex.EncodeToString(append(lo[1:], hi[30:]...))
}

func outputHashes(t *testing.T, s ringaudit.Statement) []*big.Int {
	t.Helper()
	hashes := make([]*big.Int, s.Count)
	for i := range hashes {
		hashes[i], _ = ringaudit.UtxoHash(t, s.Notes[i])
	}
	return hashes
}

func disclosureFields(t *testing.T, keys ringaudit.Keys, s ringaudit.Statement) []*big.Int {
	t.Helper()
	fields, _ := ringaudit.Disclose(t, keys.TxSk(), s.Salt(), ringaudit.PackChunks(ringaudit.AnonymousPlaintext(s)))
	return fields
}

func bytesOf(values []frontend.Variable) []byte {
	out := make([]byte, len(values))
	for i, value := range values {
		out[i] = byte(spptest.AsBigInt(value).Uint64())
	}
	return out
}

func TestRecipientEncryptionRefusals(t *testing.T) {
	keys, valid := twoByTwo(t)
	cs := testConstraintSystem(t)
	solve(t, cs, keys.Circuit(t, valid))

	otherViewing := ringaudit.Tagged(ringaudit.XPrivateKey(t, ringaudit.Scalar(0x66)).PublicKey().Bytes())
	reseal := func(s *ringaudit.Statement, plaintext [base.AnonymousOutputPlaintextLen]byte) {
		s.Deliveries[0].Ciphertext = keys.SealOutput(t, *s, 0, 0, plaintext)
	}
	for name, edit := range map[string]func(*ringaudit.Statement){
		"signing identity": func(s *ringaudit.Statement) { s.Audit.Recipients[0][5] = 0x77 },
		"viewing key": func(s *ringaudit.Statement) {
			for i, b := range otherViewing {
				s.Audit.RecipientViewingKeys[0][i] = int(b)
			}
		},
		"ring id":         func(s *ringaudit.Statement) { s.RingProgramID[0] ^= 1 },
		"ciphertext byte": func(s *ringaudit.Statement) { s.Deliveries[0].Ciphertext[7] ^= 1 },
		"kdf slot": func(s *ringaudit.Statement) {
			s.Deliveries[0].Ciphertext = keys.SealOutput(t, *s, 0, 1, ringaudit.OutputPlaintext(*s, 0))
		},
		"asset address": func(s *ringaudit.Statement) {
			s.Deliveries[0].AssetAddress[0] ^= 1
			reseal(s, ringaudit.OutputPlaintext(*s, 0))
		},
		"blinding": func(s *ringaudit.Statement) {
			plaintext := ringaudit.OutputPlaintext(*s, 0)
			plaintext[71] ^= 1
			reseal(s, plaintext)
		},
		"noncanonical blinding alias": func(s *ringaudit.Statement) {
			plaintext := ringaudit.OutputPlaintext(*s, 0)
			alias := new(big.Int).Add(spptest.AsBigInt(s.Notes[0].Blinding), ecc.BN254.ScalarField())
			alias.FillBytes(plaintext[40:72])
			reseal(s, plaintext)
		},
		"committed data hash": func(s *ringaudit.Statement) {
			s.Notes[0].DataHash = big.NewInt(5)
			keys.Deliver(t, s)
		},
		"committed ring data hash": func(s *ringaudit.Statement) {
			s.Notes[0].RingDataHash = big.NewInt(5)
			keys.Deliver(t, s)
		},
		"non-contributory recipient key": func(s *ringaudit.Statement) {
			for i := 1; i < 33; i++ {
				s.Audit.RecipientViewingKeys[0][i] = 0
			}
		},
		"padding body in a real slot": func(s *ringaudit.Statement) {
			s.Deliveries[0].Ciphertext = s.Deliveries[1].Ciphertext
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := valid
			edit(&s)
			reject(t, cs, keys.Circuit(t, s))
		})
	}

	t.Run("nullifier key", func(t *testing.T) {
		other := valid
		other.Notes[0].NullifierPk = spptest.MustNullifierPk(t, big.NewInt(21))
		elements := keys.BaseChainElementsFor(t, valid)
		elements[chainDisclosureHash] = keys.BaseChainElementsFor(t, other)[chainDisclosureHash]
		circuit := keys.Circuit(t, valid)
		circuit.PublicInputHash = spptest.MustHashChain(t, elements)
		reject(t, cs, circuit)
	})
	t.Run("body hash", func(t *testing.T) {
		elements := keys.BaseChainElementsFor(t, valid)
		elements[base.BodyChainIndex] = new(big.Int).Add(elements[base.BodyChainIndex], big.NewInt(1))
		circuit := keys.Circuit(t, valid)
		circuit.PublicInputHash = spptest.MustHashChain(t, elements)
		reject(t, cs, circuit)
	})
}

// A note leaving the ring is a scheme-3 output, its slot chains zero and carries no body.
func TestRecipientEncryptionSkipsExits(t *testing.T) {
	keys, s := twoByTwo(t)
	other, owner := ringaudit.Identity(t, 0xd4)
	s.Notes[0].OwnerPkHash = owner
	s.Notes[0].RingProgramID = big.NewInt(0)
	for i, b := range other {
		s.Audit.Recipients[0][i] = int(b)
	}
	s.Rebind(t)
	if ringaudit.BodyHashes(t, s)[0].Sign() != 0 {
		t.Fatal("an exit slot has a body hash")
	}
	solve(t, testConstraintSystem(t), keys.Circuit(t, s))
}
