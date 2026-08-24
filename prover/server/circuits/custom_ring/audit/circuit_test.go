package audit

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/iden3/go-iden3-crypto/poseidon"

	ve "zolana/prover/circuits/verifiable-encryption"
)

// The host side of this test recomputes the whole statement outside the circuit
// with crypto/ecdh, iden3 Poseidon (the same permutation the in-circuit gadget
// links its constants from) and crypto/aes. Solving the compiled R1CS against
// that witness is the cross-check that the circuit computes what the Rust host
// and program will recompute.

var (
	compileOnce sync.Once
	compiledCs  constraint.ConstraintSystem
	compileErr  error
)

func testConstraintSystem(t *testing.T) constraint.ConstraintSystem {
	t.Helper()
	compileOnce.Do(func() {
		start := time.Now()
		compiledCs, compileErr = frontend.Compile(
			ecc.BN254.ScalarField(),
			r1cs.NewBuilder,
			&Circuit{},
			frontend.WithCompressThreshold(300),
		)
		if compileErr == nil {
			t.Logf("compiled in %s: %d constraints, %d internal variables, %d secret variables",
				time.Since(start).Round(time.Millisecond),
				compiledCs.GetNbConstraints(),
				compiledCs.GetNbInternalVariables(),
				compiledCs.GetNbSecretVariables())
		}
	})
	if compileErr != nil {
		t.Fatalf("compile: %v", compileErr)
	}
	return compiledCs
}

func TestCircuitCommitmentShape(t *testing.T) {
	cs := testConstraintSystem(t)

	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok {
		t.Fatalf("unexpected commitments type %T", cs.GetCommitments())
	}
	// groth16-solana's BSB22 verifier supports exactly one commitment, over
	// private wires only: a committed public wire makes the vk parser reject the
	// key with Bsb22UnsupportedMultiCommitment.
	if len(commitments) != 1 {
		t.Fatalf("expected 1 BSB22 commitment, got %d", len(commitments))
	}
	if got := commitments[0].NbPublicCommitted; got != 0 {
		t.Fatalf("expected 0 public committed wires, got %d", got)
	}
	t.Logf("BSB22: 1 commitment over %d private wires", len(commitments[0].PrivateCommitted))
}

func TestCircuitSolvesValidWitness(t *testing.T) {
	cs := testConstraintSystem(t)
	assignment := validAssignment(t)

	solve(t, cs, assignment)
}

func TestCircuitRejectsTamperedWitness(t *testing.T) {
	cs := testConstraintSystem(t)

	tests := []struct {
		name   string
		tamper func(*testing.T, *Circuit)
	}{
		{
			name: "public input hash off by one",
			tamper: func(t *testing.T, c *Circuit) {
				hash, ok := c.PublicInputHash.(*big.Int)
				if !ok {
					t.Fatalf("unexpected public input type %T", c.PublicInputHash)
				}
				c.PublicInputHash = new(big.Int).Add(hash, big.NewInt(1))
			},
		},
		{
			name: "private tx hash not the one in the chain",
			tamper: func(_ *testing.T, c *Circuit) {
				c.PrivateTxHash = big.NewInt(7)
			},
		},
		{
			name: "plaintext scalar byte flipped",
			tamper: func(_ *testing.T, c *Circuit) {
				c.TxViewingSk[31] = 0
			},
		},
		{
			name: "auditor key off curve",
			tamper: func(_ *testing.T, c *Circuit) {
				c.AuditorPk[64] = 0
			},
		},
		{
			name: "auditor key uncompressed prefix not 4",
			tamper: func(_ *testing.T, c *Circuit) {
				c.AuditorPk[0] = 6
			},
		},
		{
			name: "witnessed byte out of range",
			tamper: func(_ *testing.T, c *Circuit) {
				c.EphSk[0] = 256
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assignment := validAssignment(t)
			test.tamper(t, assignment)

			witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatalf("new witness: %v", err)
			}
			if err := cs.IsSolved(witness); err == nil {
				t.Fatal("expected the tampered witness to be rejected")
			}
		})
	}
}

func solve(t *testing.T, cs constraint.ConstraintSystem, assignment *Circuit) {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	if err := cs.IsSolved(witness); err != nil {
		t.Fatalf("solve: %v", err)
	}
}

// validAssignment builds a fully valid witness: two scalars, an auditor key, and
// the public input hash recomputed host-side over the pinned eight-element chain.
func validAssignment(t *testing.T) *Circuit {
	t.Helper()

	txSk := scalar(t, 0x11)
	ephSk := scalar(t, 0x22)
	auditorSk := scalar(t, 0x33)

	curve := ecdh.P256()
	txPriv, err := curve.NewPrivateKey(txSk[:])
	if err != nil {
		t.Fatalf("tx private key: %v", err)
	}
	ephPriv, err := curve.NewPrivateKey(ephSk[:])
	if err != nil {
		t.Fatalf("ephemeral private key: %v", err)
	}
	auditorPriv, err := curve.NewPrivateKey(auditorSk[:])
	if err != nil {
		t.Fatalf("auditor private key: %v", err)
	}

	auditorUncompressed := uncompressed(t, auditorPriv.PublicKey().Bytes())
	txCompressed := compress(t, txPriv.PublicKey().Bytes())
	ephCompressed := compress(t, ephPriv.PublicKey().Bytes())
	auditorCompressed := compress(t, auditorPriv.PublicKey().Bytes())

	dh, err := ephPriv.ECDH(auditorPriv.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	if len(dh) != 32 {
		t.Fatalf("ecdh output length %d", len(dh))
	}

	dhLo, dhHi := hostPack32(t, dh)
	txLo, txHi := hostPack33(txCompressed)
	ephLo, ephHi := hostPack33(ephCompressed)
	auditorLo, auditorHi := hostPack33(auditorCompressed)

	sharedSecret := hostPoseidon(t, []*big.Int{
		new(big.Int).SetUint64(uint64(DomSepCRShared)),
		dhLo, dhHi,
		ephLo, ephHi,
		auditorLo, auditorHi,
	})

	key, nonce := hostKeySchedule(t, sharedSecret)
	ciphertext := hostCtrEncrypt(t, key, nonce, txSk[:])
	ciphertextHash := hostHashBytes(t, ciphertext)

	privateTxHash := big.NewInt(0xabcdef)
	publicInputHash := hostHashChain(t, []*big.Int{
		privateTxHash,
		txLo, txHi,
		auditorLo, auditorHi,
		ephLo, ephHi,
		ciphertextHash,
	})

	assignment := &Circuit{
		PublicInputHash: publicInputHash,
		PrivateTxHash:   privateTxHash,
	}
	for i, b := range txSk {
		assignment.TxViewingSk[i] = int(b)
	}
	for i, b := range ephSk {
		assignment.EphSk[i] = int(b)
	}
	for i, b := range auditorUncompressed {
		assignment.AuditorPk[i] = int(b)
	}
	return assignment
}

// scalar builds a deterministic non-zero P-256 scalar below the group order.
func scalar(t *testing.T, seed byte) [32]byte {
	t.Helper()
	var out [32]byte
	for i := range out {
		out[i] = seed ^ byte(i)
	}
	// Keep the value comfortably below the group order.
	out[0] = 0x01
	return out
}

func uncompressed(t *testing.T, publicKey []byte) [65]byte {
	t.Helper()
	if len(publicKey) != 65 {
		t.Fatalf("expected a 65-byte uncompressed key, got %d bytes", len(publicKey))
	}
	var out [65]byte
	copy(out[:], publicKey)
	if out[0] != 4 {
		t.Fatalf("expected the 0x04 prefix, got %#x", out[0])
	}
	return out
}

// compress mirrors p256.CompressPubkey host-side: (0x02 + parity(y)) || x.
func compress(t *testing.T, publicKey []byte) [33]byte {
	t.Helper()
	key := uncompressed(t, publicKey)
	var out [33]byte
	out[0] = 2 + (key[64] & 1)
	copy(out[1:], key[1:33])
	return out
}

// hostPack32 mirrors Pack32To2FECircuit: lo = 0x00 || bytes[0..31], hi = bytes[31].
func hostPack32(t *testing.T, bytes []byte) (lo, hi *big.Int) {
	t.Helper()
	if len(bytes) != 32 {
		t.Fatalf("hostPack32: expected 32 bytes, got %d", len(bytes))
	}
	return new(big.Int).SetBytes(bytes[:31]), new(big.Int).SetUint64(uint64(bytes[31]))
}

// hostPack33 mirrors Pack33To2FECircuit: lo = 0x00 || key[0..31],
// hi = key[31] * 256 + key[32].
func hostPack33(key [33]byte) (lo, hi *big.Int) {
	lo = new(big.Int).SetBytes(key[:31])
	hi = new(big.Int).SetUint64(uint64(key[31])<<8 | uint64(key[32]))
	return lo, hi
}

func hostPoseidon(t *testing.T, inputs []*big.Int) *big.Int {
	t.Helper()
	out, err := poseidon.Hash(inputs)
	if err != nil {
		t.Fatalf("poseidon: %v", err)
	}
	return out
}

// hostHashChain mirrors gadget.HashChain: h = inputs[0], h = Poseidon(h, next).
func hostHashChain(t *testing.T, inputs []*big.Int) *big.Int {
	t.Helper()
	if len(inputs) == 0 {
		return big.NewInt(0)
	}
	h := inputs[0]
	for _, input := range inputs[1:] {
		h = hostPoseidon(t, []*big.Int{h, input})
	}
	return h
}

// hostHashBytes mirrors gadget.HashBytes (== zolana_hasher hash_bytes): pack the
// bytes into big-endian 31-byte chunks, then hash-chain the chunks.
func hostHashBytes(t *testing.T, bytes []byte) *big.Int {
	t.Helper()
	const chunkSize = 31
	fields := make([]*big.Int, 0, (len(bytes)+chunkSize-1)/chunkSize)
	for offset := 0; offset < len(bytes); offset += chunkSize {
		end := offset + chunkSize
		if end > len(bytes) {
			end = len(bytes)
		}
		fields = append(fields, new(big.Int).SetBytes(bytes[offset:end]))
	}
	return hostHashChain(t, fields)
}

// hostKeySchedule mirrors ve.KeySchedule with auditEncInfo as the info string.
func hostKeySchedule(t *testing.T, sharedSecret *big.Int) ([32]byte, [12]byte) {
	t.Helper()
	// The info string is shorter than one 31-byte chunk, so it packs into a
	// single field element.
	infoField := new(big.Int).SetBytes([]byte(auditEncInfo))
	siloed := hostPoseidon(t, []*big.Int{
		new(big.Int).SetUint64(uint64(ve.DomSepSilo)),
		sharedSecret,
		infoField,
	})
	keyLo := hostPoseidon(t, []*big.Int{new(big.Int).SetUint64(uint64(ve.DomSepKey)), siloed})
	keyHi := hostPoseidon(t, []*big.Int{new(big.Int).SetUint64(uint64(ve.DomSepKey + 1)), siloed})
	nonceRaw := hostPoseidon(t, []*big.Int{new(big.Int).SetUint64(uint64(ve.DomSepNonce)), siloed})

	keyLoBytes := feBytes(keyLo)
	keyHiBytes := feBytes(keyHi)
	var key [32]byte
	copy(key[:16], keyHiBytes[16:])
	copy(key[16:], keyLoBytes[16:])

	var nonce [12]byte
	nonceBytes := feBytes(nonceRaw)
	copy(nonce[:], nonceBytes[20:])
	return key, nonce
}

func feBytes(value *big.Int) [32]byte {
	var out [32]byte
	value.FillBytes(out[:])
	return out
}

// hostCtrEncrypt mirrors aes.CTREncrypt: the counter block is
// nonce || 0x00000001 incremented once before the first block, so the first
// keystream block uses nonce || 0x00000002.
func hostCtrEncrypt(t *testing.T, key [32]byte, nonce [12]byte, plaintext []byte) []byte {
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
