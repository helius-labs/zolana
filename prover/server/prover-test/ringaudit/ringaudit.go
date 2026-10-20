// Package ringaudit recomputes the audit block of package base on the host.
package ringaudit

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	ve "github.com/helius-labs/zolana/prover/server/circuits/encryption"
	base "github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Mirrors the unexported key-schedule info string of package base.
const auditEncInfo = "CRING/adt1"

type Keys struct {
	txSk      [32]byte
	ephSk     [32]byte
	txPk      [33]byte
	ephPk     [33]byte
	auditorPk [32]byte
	dh        [32]byte
}

func DefaultKeys(t testing.TB) Keys {
	t.Helper()
	txSk := Clamped(Scalar(0x11))
	ephSk := Scalar(0x22)
	txPriv := XPrivateKey(t, txSk)
	ephPriv := XPrivateKey(t, ephSk)
	auditorPriv := XPrivateKey(t, Scalar(0x33))

	dh, err := ephPriv.ECDH(auditorPriv.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	return Keys{
		txSk:      txSk,
		ephSk:     ephSk,
		txPk:      Tagged(txPriv.PublicKey().Bytes()),
		ephPk:     Tagged(ephPriv.PublicKey().Bytes()),
		auditorPk: [32]byte(auditorPriv.PublicKey().Bytes()),
		dh:        [32]byte(dh),
	}
}

// WithTxScalar witnesses the clamped encoding of secret and publishes its key.
func (k Keys) WithTxScalar(t testing.TB, secret [32]byte) Keys {
	t.Helper()
	k.txSk = Clamped(secret)
	k.txPk = Tagged(XPrivateKey(t, k.txSk).PublicKey().Bytes())
	return k
}

// WithRawTxScalar witnesses secret unclamped under the key its clamping publishes.
func (k Keys) WithRawTxScalar(t testing.TB, secret [32]byte) Keys {
	k = k.WithTxScalar(t, secret)
	k.txSk = secret
	return k
}

// WithInvalidTxTag uses a tag the X25519 viewing-key decoder must reject.
func (k Keys) WithInvalidTxTag() Keys {
	k.txPk[0] = 2
	return k
}

// WithInvalidEphTag uses a tag the auditor envelope decoder must reject.
func (k Keys) WithInvalidEphTag() Keys {
	k.ephPk[0] = 2
	return k
}

// WithEphScalar computes an honest envelope, including RFC 7748 clamping.
func (k Keys) WithEphScalar(t testing.TB, scalar [32]byte) Keys {
	t.Helper()
	key := XPrivateKey(t, scalar)
	peer, err := ecdh.X25519().NewPublicKey(k.auditorPk[:])
	if err != nil {
		t.Fatal(err)
	}
	dh, err := key.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	k.ephSk, k.ephPk, k.dh = scalar, Tagged(key.PublicKey().Bytes()), [32]byte(dh)
	return k
}

func (k Keys) TxSk() [32]byte {
	return k.txSk
}

func (k Keys) EphSk() [32]byte {
	return k.ephSk
}

func (k Keys) AuditorPk() [32]byte {
	return k.auditorPk
}

type Sealed struct {
	AuditorLo      *big.Int
	AuditorHi      *big.Int
	EphLo          *big.Int
	EphHi          *big.Int
	CiphertextHash *big.Int
}

// Mirrors base.Envelope.Seal.
func (k Keys) Seal(t testing.TB, plaintext []byte, info string) Sealed {
	t.Helper()
	dhLo, dhHi := pack32(k.dh)
	ephLo, ephHi := pack33(k.ephPk)
	auditorLo, auditorHi := pack33(Tagged(k.auditorPk[:]))

	sharedSecret := spptest.MustPoseidon(t, 8, []*big.Int{
		tag(base.DomSepCRShared),
		dhLo, dhHi,
		ephLo, ephHi,
		auditorLo, auditorHi,
	})
	key, nonce := keySchedule(t, sharedSecret, info)
	ciphertext, err := protocol.HashBytes(ctrEncrypt(t, key, nonce, plaintext))
	return Sealed{
		AuditorLo:      auditorLo,
		AuditorHi:      auditorHi,
		EphLo:          ephLo,
		EphHi:          ephHi,
		CiphertextHash: spptest.MustHash(t, ciphertext, err),
	}
}

// Statement is the audit witness with the slots it discloses.
type Statement struct {
	Audit   base.Audit
	Outputs [base.AuditOutputSlots]base.AuditOutputWires
	Count   int
	// An anonymous ring discloses these and opens private_tx_hash from them.
	NIn               int
	Inputs            []base.AuditUtxoWires
	ShortOrdinary     bool
	Notes             [base.AuditOutputSlots]base.AuditUtxoWires
	PrivateTxBlinding *big.Int
}

// Statement discloses one zero output.
func (k Keys) Statement(privateTxHash *big.Int) Statement {
	s := Statement{Audit: base.Audit{PrivateTxHash: privateTxHash, Anonymous: 0}, Count: 1,
		Inputs: make([]base.AuditUtxoWires, base.AuditInputSlots), PrivateTxBlinding: big.NewInt(0)}
	setBytes(s.Audit.TxViewingSk[:], k.txSk[:])
	setBytes(s.Audit.EphSk[:], k.ephSk[:])
	setBytes(s.Audit.AuditorPk[:], k.auditorPk[:])
	setBytes(s.Audit.Salt[:], make([]byte, 16))
	setBytes(s.Audit.Sender[:], make([]byte, base.IdentityLen))
	for i := range s.Outputs {
		s.Outputs[i] = base.AuditOutputWires{
			Domain: big.NewInt(0), TreeID: big.NewInt(0), OwnerHash: big.NewInt(0),
			Asset: big.NewInt(0), Amount: big.NewInt(0), Blinding: big.NewInt(0),
			DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0),
		}
		s.Notes[i] = zeroUtxo()
		setBytes(s.Audit.Recipients[i][:], make([]byte, base.IdentityLen))
		setBytes(s.Audit.RecipientViewingKeys[i][:], make([]byte, 33))
	}
	for i := range s.Inputs {
		s.Inputs[i] = zeroUtxo()
	}
	return s
}

// AnonymousStatement spends one note of the sender into one ring note of the recipient.
func (k Keys) AnonymousStatement(t testing.TB) Statement {
	t.Helper()
	s := k.Statement(big.NewInt(0))
	s.Audit.Anonymous = 1
	s.NIn = 1
	s.PrivateTxBlinding = big.NewInt(0x5b1d)
	sender, senderHash := Identity(t, 0xa1)
	recipient, recipientHash := Identity(t, 0xb2)
	setBytes(s.Audit.Sender[:], sender[:])
	setBytes(s.Audit.Recipients[0][:], recipient[:])
	viewing := Tagged(XPrivateKey(t, Scalar(0x55)).PublicKey().Bytes())
	setBytes(s.Audit.RecipientViewingKeys[0][:], viewing[:])
	s.Inputs[0] = base.AuditUtxoWires{
		Domain: big.NewInt(protocol.UtxoDomain), TreeID: big.NewInt(3),
		OwnerPkHash: senderHash, NullifierPk: spptest.MustNullifierPk(t, big.NewInt(7)),
		Asset: big.NewInt(10), Amount: big.NewInt(100), Blinding: big.NewInt(51),
		DataHash: big.NewInt(0), RingDataHash: big.NewInt(77), RingProgramID: big.NewInt(90),
	}
	s.Notes[0] = base.AuditUtxoWires{
		Domain: big.NewInt(protocol.UtxoDomain), TreeID: big.NewInt(9),
		OwnerPkHash: recipientHash, NullifierPk: spptest.MustNullifierPk(t, big.NewInt(20)),
		Asset: big.NewInt(10), Amount: big.NewInt(100), Blinding: big.NewInt(61),
		DataHash: big.NewInt(0), RingDataHash: big.NewInt(78), RingProgramID: big.NewInt(90),
	}
	s.Rebind(t)
	return s
}

// Rebind opens private_tx_hash from the anonymous slots.
func (s *Statement) Rebind(t testing.TB) {
	t.Helper()
	var inputs, outputs []*big.Int
	for _, input := range s.Inputs[:s.NIn] {
		if hash, utxo := UtxoHash(t, input); utxo {
			inputs = append(inputs, hash)
		}
	}
	for _, output := range s.Notes[:s.Count] {
		if hash, utxo := UtxoHash(t, output); utxo {
			outputs = append(outputs, hash)
		}
	}
	s.Audit.PrivateTxHash = spptest.MustPrivateTxHash(t, inputs, outputs, nil, s.PrivateTxBlinding)
}

// Circuit is the base assignment that proves the statement.
func (k Keys) Circuit(t testing.TB, s Statement) *base.CustomRingBaseCircuit {
	t.Helper()
	c := &base.CustomRingBaseCircuit{
		PublicInputHash:   spptest.MustHashChain(t, k.ChainElementsFor(t, s)),
		Audit:             s.Audit,
		NOut:              s.Count,
		Outputs:           s.Outputs,
		NIn:               s.NIn,
		AnonymousOutputs:  s.Notes,
		PrivateTxBlinding: s.PrivateTxBlinding,
	}
	copy(c.Inputs[:], s.Inputs)
	return c
}

// ChainElements returns the base chain of a one-slot zero-output statement.
func (k Keys) ChainElements(t testing.TB, privateTxHash *big.Int) []*big.Int {
	return k.ChainElementsFor(t, k.Statement(privateTxHash))
}

func (k Keys) ChainElementsFor(t testing.TB, s Statement) []*big.Int {
	t.Helper()
	txLo, txHi := pack33(k.txPk)
	sealed := k.Seal(t, k.txSk[:], auditEncInfo)
	anonymous := spptest.AsBigInt(s.Audit.Anonymous).Sign() != 0
	outputHashes := make([]*big.Int, s.Count)
	plaintext := make([]*big.Int, 0, base.AuditOutputSlots*base.AuditOutputFieldCount)
	for i, output := range s.Outputs {
		if anonymous {
			if i < s.Count {
				outputHashes[i], _ = UtxoHash(t, s.Notes[i])
			}
			continue
		}
		fields := spptest.ToBigInts([]frontend.Variable{output.Domain, output.TreeID, output.OwnerHash, output.Asset, output.Amount,
			output.Blinding, output.DataHash, output.RingDataHash, output.RingProgramID})
		if i >= s.Count {
			plaintext = append(plaintext, spptest.RepeatBigInt(big.NewInt(0), base.AuditOutputFieldCount)...)
			continue
		}
		outputHashes[i] = spptest.MustUtxoHash(t, protocol.Utxo{
			Domain: fields[0], Owner: fields[2], Asset: fields[3], Amount: fields[4], Blinding: fields[5],
			DataHash: fields[6], RingDataHash: fields[7], RingProgramID: fields[8],
		}, fields[1])
		plaintext = append(plaintext, fields...)
	}
	if anonymous {
		plaintext = PackChunks(AnonymousPlaintext(s))
	} else if s.ShortOrdinary {
		plaintext = plaintext[:2*base.AuditOutputFieldCount]
	}
	var salt [16]byte
	for i, value := range s.Audit.Salt {
		salt[i] = byte(spptest.AsBigInt(value).Uint64())
	}
	_, disclosureHash := Disclose(t, k.txSk, salt, plaintext)
	return []*big.Int{
		spptest.AsBigInt(s.Audit.PrivateTxHash),
		txLo, txHi,
		sealed.AuditorLo, sealed.AuditorHi,
		sealed.EphLo, sealed.EphHi,
		sealed.CiphertextHash,
		spptest.MustHashChain4(t, outputHashes),
		new(big.Int).SetBytes(salt[:]),
		disclosureHash,
		spptest.AsBigInt(s.Audit.Anonymous),
	}
}

// Anonymous slot widths, each zero padded to whole 31-byte chunks.
const (
	HeaderBytes = 62
	InputBytes  = 93
	OutputBytes = 248
)

// AnonymousPlaintext mirrors the anonymous slot layout of package base, a dummy slot is all zero.
func AnonymousPlaintext(s Statement) []byte {
	out := make([]byte, HeaderBytes, HeaderBytes+s.NIn*InputBytes+s.Count*OutputBytes)
	copy(out, bytesOf(s.Audit.Sender[:]))
	for _, input := range s.Inputs[:s.NIn] {
		slot := make([]byte, InputBytes)
		if isUtxo(input) {
			v := spptest.AsBigInt
			binary.BigEndian.PutUint16(slot, uint16(v(input.TreeID).Uint64()))
			binary.BigEndian.PutUint64(slot[2:], v(input.Amount).Uint64())
			v(input.Asset).FillBytes(slot[10:42])
			v(input.Blinding).FillBytes(slot[42:74])
		}
		out = append(out, slot...)
	}
	for i, output := range s.Notes[:s.Count] {
		slot := make([]byte, OutputBytes)
		if isUtxo(output) {
			v := spptest.AsBigInt
			copy(slot, bytesOf(s.Audit.Recipients[i][:]))
			copy(slot[33:], bytesOf(s.Audit.RecipientViewingKeys[i][:]))
			v(output.NullifierPk).FillBytes(slot[66:98])
			binary.BigEndian.PutUint64(slot[98:], v(output.Amount).Uint64())
			v(output.Asset).FillBytes(slot[106:138])
			v(output.Blinding).FillBytes(slot[138:170])
			v(output.DataHash).FillBytes(slot[170:202])
			v(output.RingDataHash).FillBytes(slot[202:234])
			if v(output.RingProgramID).Sign() != 0 {
				slot[234] = 1
			}
		}
		out = append(out, slot...)
	}
	return out
}

// PackChunks reads every 31 bytes as one big-endian field.
func PackChunks(plaintext []byte) []*big.Int {
	fields := make([]*big.Int, 0, len(plaintext)/31)
	for start := 0; start < len(plaintext); start += 31 {
		fields = append(fields, new(big.Int).SetBytes(plaintext[start:min(start+31, len(plaintext))]))
	}
	return fields
}

// UtxoHash mirrors base.AuditUtxoWires.Hash.
func UtxoHash(t testing.TB, w base.AuditUtxoWires) (*big.Int, bool) {
	t.Helper()
	v := spptest.AsBigInt
	owner := big.NewInt(0)
	if isUtxo(w) {
		owner = spptest.MustOwnerHash(t, v(w.OwnerPkHash), v(w.NullifierPk))
	}
	return spptest.MustUtxoHash(t, protocol.Utxo{
		Domain: v(w.Domain), Owner: owner, Asset: v(w.Asset), Amount: v(w.Amount),
		Blinding: v(w.Blinding), DataHash: v(w.DataHash), RingDataHash: v(w.RingDataHash),
		RingProgramID: v(w.RingProgramID),
	}, v(w.TreeID)), isUtxo(w)
}

// Identity is the Ed25519 owner tag and a key of seed bytes, with its owner pk hash.
func Identity(t testing.TB, seed byte) ([base.IdentityLen]byte, *big.Int) {
	t.Helper()
	var identity [base.IdentityLen]byte
	identity[0] = protocol.SolanaOwnerTag
	for i := 1; i < len(identity); i++ {
		identity[i] = seed
	}
	hash, err := protocol.HashBytes(identity[:])
	return identity, spptest.MustHash(t, hash, err)
}

func isUtxo(w base.AuditUtxoWires) bool {
	return spptest.AsBigInt(w.Domain).Int64() == protocol.UtxoDomain
}

func zeroUtxo() base.AuditUtxoWires {
	return base.AuditUtxoWires{
		Domain: big.NewInt(0), TreeID: big.NewInt(0), OwnerPkHash: big.NewInt(0), NullifierPk: big.NewInt(0),
		Asset: big.NewInt(0), Amount: big.NewInt(0), Blinding: big.NewInt(0), DataHash: big.NewInt(0),
		RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0),
	}
}

func bytesOf(values []frontend.Variable) []byte {
	out := make([]byte, len(values))
	for i, value := range values {
		out[i] = byte(spptest.AsBigInt(value).Uint64())
	}
	return out
}

// DisclosurePad mirrors the base disclosure pad, Poseidon(seed, i) over the keyed seed.
func DisclosurePad(t testing.TB, key [32]byte, salt [16]byte, n int) []*big.Int {
	t.Helper()
	keyLo, keyHi := pack32(key)
	seed := spptest.MustPoseidon(t, 5, []*big.Int{new(big.Int).SetUint64(base.OutputDisclosureDomain), keyLo, keyHi, new(big.Int).SetBytes(salt[:])})
	pad := make([]*big.Int, n)
	for i := range pad {
		pad[i] = spptest.MustPoseidon(t, 3, []*big.Int{seed, big.NewInt(int64(i))})
	}
	return pad
}

// Disclose adds the pad to every field and folds the ciphertext with HashChain4, as base.Audit.Define does.
func Disclose(t testing.TB, key [32]byte, salt [16]byte, fields []*big.Int) (ciphertext []*big.Int, hash *big.Int) {
	t.Helper()
	pad := DisclosurePad(t, key, salt, len(fields))
	ciphertext = make([]*big.Int, len(fields))
	for i, field := range fields {
		ciphertext[i] = new(big.Int).Add(field, pad[i])
		ciphertext[i].Mod(ciphertext[i], ecc.BN254.ScalarField())
	}
	return ciphertext, spptest.MustHashChain4(t, ciphertext)
}

// Scalar is byte i = seed ^ i with a 0x01 lead byte, the fixture every cross-language vector derives from.
func Scalar(seed byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = seed ^ byte(i)
	}
	out[0] = 0x01
	return out
}

// Clamped is the RFC 7748 clamping of secret, the one encoding the circuit accepts as plaintext.
func Clamped(secret [32]byte) [32]byte {
	secret[0] &= 248
	secret[31] = (secret[31] & 127) | 64
	return secret
}

// Mirrors gadget.PackBytesBE over 32 bytes.
func pack32(bytes [32]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(bytes[:31]), new(big.Int).SetUint64(uint64(bytes[31]))
}

// Mirrors gadget.PackBytesBE over 33 bytes.
func pack33(key [33]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(key[:31]), new(big.Int).SetUint64(uint64(key[31])<<8 | uint64(key[32]))
}

// Mirrors ve.KeySchedule.
func keySchedule(t testing.TB, sharedSecret *big.Int, info string) (key [32]byte, nonce [12]byte) {
	t.Helper()
	if info == auditEncInfo {
		headTag := new(big.Int).SetBytes(append([]byte(info), 0))
		tailTag := new(big.Int).SetBytes(append([]byte(info), 1))
		head := spptest.MustFieldBytes(t, spptest.MustPoseidon(t, 3, []*big.Int{headTag, sharedSecret}))
		tail := spptest.MustFieldBytes(t, spptest.MustPoseidon(t, 3, []*big.Int{tailTag, sharedSecret}))
		copy(key[:31], head[1:])
		key[31] = tail[19]
		copy(nonce[:], tail[20:])
		return key, nonce
	}
	siloed := spptest.MustPoseidon(t, 4, []*big.Int{
		tag(ve.DomSepSilo),
		sharedSecret,
		new(big.Int).SetBytes([]byte(info)),
	})
	keyLo := spptest.MustFieldBytes(t, spptest.MustPoseidon(t, 3, []*big.Int{tag(ve.DomSepKey), siloed}))
	keyHi := spptest.MustFieldBytes(t, spptest.MustPoseidon(t, 3, []*big.Int{tag(ve.DomSepKey + 1), siloed}))
	nonceRaw := spptest.MustFieldBytes(t, spptest.MustPoseidon(t, 3, []*big.Int{tag(ve.DomSepNonce), siloed}))

	copy(key[:16], keyHi[16:])
	copy(key[16:], keyLo[16:])
	copy(nonce[:], nonceRaw[20:])
	return key, nonce
}

// Mirrors aes.Cipher.CTREncrypt, the first keystream block counts from nonce || 2.
func ctrEncrypt(t testing.TB, key [32]byte, nonce [12]byte, plaintext []byte) []byte {
	t.Helper()
	block, err := stdaes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	var counter [16]byte
	copy(counter[:12], nonce[:])
	counter[15] = 2

	ciphertext := make([]byte, len(plaintext))
	cipher.NewCTR(block, counter[:]).XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

func tag(value uint32) *big.Int {
	return new(big.Int).SetUint64(uint64(value))
}

func setBytes(dst []frontend.Variable, src []byte) {
	for i, b := range src {
		dst[i] = int(b)
	}
}

func XPrivateKey(t testing.TB, scalar [32]byte) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Tagged is the 0x04 || u encoding of an X25519 key.
func Tagged(key []byte) [33]byte {
	var out [33]byte
	out[0] = 4
	copy(out[1:], key)
	return out
}
