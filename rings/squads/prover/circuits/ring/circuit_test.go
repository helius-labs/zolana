package squadsring_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"math/big"
	"testing"

	. "circuits/ring"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"circuits/ringutils"
	"github.com/helius-labs/zolana/prover/server/prover-test/poseidon"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
)

// TestTransferCircuitCompiles is a smoke test: it confirms the transfer-shape
// circuit compiles to R1CS. This shape runs X25519 key agreement
// (tx_viewing_pk derivation and the recipient ECDH), so it is large.
func TestTransferCircuitCompiles(t *testing.T) {
	circuit := NewTransferCircuit(2)
	if cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300)); err != nil {
		t.Fatalf("compile squads_ring transfer circuit: %v", err)
	} else if got := len(cs.GetCommitments().CommitmentIndexes()); got != 1 {
		t.Fatalf("commitment count: got %d want 1", got)
	}
}

// TestWithdrawalCircuitCompiles confirms the withdrawal-shape (1-out) circuit
// compiles. It has no recipient, so no in-circuit ECDH.
func TestWithdrawalCircuitCompiles(t *testing.T) {
	circuit := NewWithdrawalCircuit(1)
	if cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300)); err != nil {
		t.Fatalf("compile squads_ring withdrawal circuit: %v", err)
	} else if got := len(cs.GetCommitments().CommitmentIndexes()); got != 1 {
		t.Fatalf("commitment count: got %d want 1", got)
	}
}

func TestTransferWitnessSolvedBothReal(t *testing.T) {
	a := buildTransferWitness(t, []int64{5, 7}, []int64{0})
	if err := test.IsSolved(NewTransferCircuit(2), a, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("transfer witness not solved: %v", err)
	}
}

func TestTransferWitnessSolvedWithDummyInput(t *testing.T) {
	a := buildTransferWitness(t, []int64{12, 0}, []int64{1})
	if err := test.IsSolved(NewTransferCircuit(2), a, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("dummy-input transfer witness not solved: %v", err)
	}
}

// TestTransferRejectsDummyWithNonzeroAmount keeps value conservation and the
// private_tx_hash fold consistent (the dummy slot contributes 0 either way), so
// the only violated constraint is the dummy amount pin.
func TestTransferRejectsDummyWithNonzeroAmount(t *testing.T) {
	a := buildTransferWitness(t, []int64{11, 1}, []int64{1})
	if err := test.IsSolved(NewTransferCircuit(2), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected dummy-amount failure, got solved")
	}
}

// External data no longer enters main's private transaction hash. The ring
// transcript must bind it separately so ciphertext and view-tag substitutions
// cannot reuse an existing ring proof.
func TestTransferRejectsChangedExternalData(t *testing.T) {
	a := buildTransferWitness(t, []int64{5, 7}, []int64{0})
	a.Transaction.ExternalDataHash = 0
	if err := test.IsSolved(NewTransferCircuit(2), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("changed external data solved")
	}
}

func TestTransferRejectsChangedRecipient(t *testing.T) {
	a := buildTransferWitness(t, []int64{5, 7}, []int64{0})
	a.Recipient.ViewingPubkey[0] = 3
	if err := test.IsSolved(NewTransferCircuit(2), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("changed recipient key solved")
	}
}

// Ring KDF constants, mirroring circuits/ring-utils/poseidon_kdf.go and
// sender.go byte-for-byte.
var (
	kdfDomainSep   = new(big.Int).SetBytes([]byte("TSPP/kdf"))
	labelTxViewing = new(big.Int).SetBytes([]byte("TSPP/tx_viewing"))
	labelBlinding  = new(big.Int).SetBytes([]byte("blinding"))

	domSepSharedSecret = big.NewInt(0x43545f53)
	domSepSilo         = big.NewInt(0x544d5349)
	domSepKey          = big.NewInt(0x544d534b)
	domSepKey1         = big.NewInt(0x544d534c)
	domSepNonce        = big.NewInt(0x544d534e)
)

// buildTransferWitness assembles a solved (2,2) transfer witness off-circuit,
// mirroring the in-circuit KDF/AES-CTR/ECDH byte-for-byte. inputsDummy flags
// Inputs[1..] as DummyDomain slots, which contribute 0 to the private_tx_hash
// input fold.
func buildTransferWitness(t *testing.T, inputAmounts []int64, inputsDummy []int64) *Circuit {
	t.Helper()
	curve := ecdh.X25519()

	senderOwnerKey := big.NewInt(0xA11CE)
	senderNullifierSecret := big.NewInt(19)
	senderNullifierPk := mustHash(t, []*big.Int{senderNullifierSecret})
	senderOwnerHash := mustHash(t, []*big.Int{senderOwnerKey, senderNullifierPk})

	sharedViewingSk := big.NewInt(0x5EED)
	skLow, skHigh := splitU128(sharedViewingSk)
	sharedViewingCommitment := mustHash(t, []*big.Int{skLow, skHigh})

	recipientOwnerKey := big.NewInt(0xB0B)
	recipientNullifierSecret := big.NewInt(23)
	recipientNullifierPk := mustHash(t, []*big.Int{recipientNullifierSecret})
	recipientOwnerHash := mustHash(t, []*big.Int{recipientOwnerKey, recipientNullifierPk})

	recipientSk, err := curve.NewPrivateKey(leftPad32(big.NewInt(7)))
	if err != nil {
		t.Fatal(err)
	}
	var rpkComp [33]byte
	rpkComp[0] = 4
	copy(rpkComp[1:], recipientSk.PublicKey().Bytes())

	asset := big.NewInt(1)
	treeID := big.NewInt(7)
	ringProgramID := big.NewInt(0x5151)
	sum := int64(0)
	inUtxos := make([]protocol.Utxo, len(inputAmounts))
	inHashes := make([]*big.Int, len(inputAmounts))
	for i, amount := range inputAmounts {
		sum += amount
		domain := big.NewInt(protocol.UtxoDomain)
		owner := senderOwnerHash
		blinding := big.NewInt(int64(0x1111 * (i + 1)))
		programID := ringProgramID
		if i > 0 && inputsDummy[i-1] == 1 {
			domain = big.NewInt(protocol.DummyDomain)
			owner = big.NewInt(0)
			programID = big.NewInt(0)
		}
		inUtxos[i] = protocol.Utxo{
			Domain:        domain,
			Owner:         owner,
			Asset:         asset,
			Amount:        big.NewInt(amount),
			Blinding:      blinding,
			DataHash:      big.NewInt(0),
			RingDataHash:  big.NewInt(0),
			RingProgramID: programID,
		}
		h, err := protocol.UtxoHash(inUtxos[i], treeID)
		if err != nil {
			t.Fatal(err)
		}
		inHashes[i] = h
	}

	firstNullifier, err := protocol.Nullifier(inHashes[0], inUtxos[0].Blinding, senderNullifierSecret)
	if err != nil {
		t.Fatal(err)
	}
	viewRoot := mustHash(t, []*big.Int{kdfDomainSep, skLow, skHigh})
	txViewingSecret := mustHash(t, []*big.Int{kdfDomainSep, viewRoot, labelTxViewing})
	txViewingSk := mustHash(t, []*big.Int{kdfDomainSep, txViewingSecret, firstNullifier})

	blindingSeed := mustHash(t, []*big.Int{kdfDomainSep, txViewingSk, labelBlinding})
	outputBlindingSeed, err := protocol.OutputBlindingSeed(firstNullifier, blindingSeed)
	if err != nil {
		t.Fatal(err)
	}
	changeBlinding, err := protocol.OutputBlinding(firstNullifier, outputBlindingSeed, 0)
	if err != nil {
		t.Fatal(err)
	}
	recipientBlinding, err := protocol.OutputBlinding(firstNullifier, outputBlindingSeed, 1)
	if err != nil {
		t.Fatal(err)
	}
	privateTxBlinding, err := protocol.PrivateTxBlinding(firstNullifier, blindingSeed)
	if err != nil {
		t.Fatal(err)
	}

	recipientAmount := big.NewInt(7)
	changeAmount := big.NewInt(sum - 7)
	changeUtxo := protocol.Utxo{
		Domain:        big.NewInt(protocol.UtxoDomain),
		Owner:         senderOwnerHash,
		Asset:         asset,
		Amount:        changeAmount,
		Blinding:      changeBlinding,
		DataHash:      big.NewInt(0),
		RingDataHash:  big.NewInt(0),
		RingProgramID: ringProgramID,
	}
	recipientUtxo := protocol.Utxo{
		Domain:        big.NewInt(protocol.UtxoDomain),
		Owner:         recipientOwnerHash,
		Asset:         asset,
		Amount:        recipientAmount,
		Blinding:      recipientBlinding,
		DataHash:      big.NewInt(0),
		RingDataHash:  big.NewInt(0),
		RingProgramID: ringProgramID,
	}
	changeHash, err := protocol.UtxoHash(changeUtxo, treeID)
	if err != nil {
		t.Fatal(err)
	}
	recipientHash, err := protocol.UtxoHash(recipientUtxo, treeID)
	if err != nil {
		t.Fatal(err)
	}

	externalDataHash := big.NewInt(0xABCDEF)
	inputFold := make([]*big.Int, len(inputAmounts))
	inputFold[0] = inHashes[0]
	for i := 1; i < len(inputAmounts); i++ {
		if inputsDummy[i-1] == 1 {
			inputFold[i] = big.NewInt(0)
		} else {
			inputFold[i] = inHashes[i]
		}
	}
	addressHashes := make([]*big.Int, len(inputAmounts))
	for i := range addressHashes {
		addressHashes[i] = big.NewInt(0)
	}
	privateTxHash, err := protocol.PrivateTxHash(inputFold, []*big.Int{changeHash, recipientHash}, addressHashes, privateTxBlinding)
	if err != nil {
		t.Fatal(err)
	}

	senderKey, senderNonce := keySchedule(t, txViewingSk)
	senderCt := ctrEncrypt(t, senderKey, senderNonce, transferPlaintext(changeAmount, asset, nil))
	senderCtHash := hashChain(t, packBytesBE(senderCt, 31))

	ephemeralSk, err := curve.NewPrivateKey(leftPad32(txViewingSk))
	if err != nil {
		t.Fatal(err)
	}
	var txViewingPkComp [33]byte
	txViewingPkComp[0] = 4
	copy(txViewingPkComp[1:], ephemeralSk.PublicKey().Bytes())
	dhBytes, err := ephemeralSk.ECDH(recipientSk.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	var dh [32]byte
	copy(dh[:], dhBytes)
	dhLo, dhHi := pack32(dh)
	ephLo, ephHi := pack33(txViewingPkComp)
	rpkLo, rpkHi := pack33(rpkComp)
	sharedSecret := mustHash(t, []*big.Int{domSepSharedSecret, dhLo, dhHi, ephLo, ephHi, rpkLo, rpkHi})

	recipientKey, recipientNonce := keySchedule(t, sharedSecret)
	recipientCt := ctrEncrypt(t, recipientKey, recipientNonce, transferPlaintext(recipientAmount, asset, recipientBlinding))
	recipientCtHash := hashChain(t, packBytesBE(recipientCt, 31))

	senderAccountHash := mustHash(t, []*big.Int{senderOwnerKey, sharedViewingCommitment, senderNullifierPk})
	recipientAccountHash := mustHash(t, []*big.Int{recipientOwnerKey, rpkLo, rpkHi, recipientNullifierPk})

	publicInputHash := hashChain(t, []*big.Int{
		privateTxHash,
		externalDataHash,
		big.NewInt(0),
		senderAccountHash,
		senderCtHash,
		ephLo, ephHi,
		recipientAccountHash,
		recipientCtHash,
		big.NewInt(0),
	})

	a := NewTransferCircuit(len(inputAmounts))
	for i := range inUtxos {
		a.Transaction.Inputs[i] = ringUtxo(inUtxos[i], treeID)
	}
	a.Transaction.Outputs[0] = ringUtxo(changeUtxo, treeID)
	a.Transaction.Outputs[1] = ringUtxo(recipientUtxo, treeID)
	a.Transaction.ExternalDataHash = externalDataHash

	a.Sender.Account.Public.Owner = senderOwnerKey
	a.Sender.Account.Public.SharedViewingSecretKeyCommitment = sharedViewingCommitment
	a.Sender.Account.Public.NullifierPubkey = senderNullifierPk
	a.Sender.Account.Private.NullifierSecret = senderNullifierSecret
	for i, b := range leftPad32(sharedViewingSk) {
		a.Sender.Account.Private.SharedViewingSecretKey[i] = b
	}

	a.Recipient.Owner = recipientOwnerKey
	a.Recipient.NullifierPubkey = recipientNullifierPk
	for i := 0; i < 33; i++ {
		a.Recipient.ViewingPubkey[i] = big.NewInt(int64(rpkComp[i]))
	}

	a.Proposal.Amount = big.NewInt(0)
	a.Proposal.Recipient = big.NewInt(0)
	a.Proposal.Blinding = big.NewInt(0)
	a.Proposal.PublicAmount = big.NewInt(0)
	a.EnableProposalHash = big.NewInt(0)
	a.PublicAmount = big.NewInt(0)
	a.PublicInputHash = publicInputHash

	return a
}

func transferPlaintext(amount, asset, blinding *big.Int) []byte {
	var amountB [8]byte
	amount.FillBytes(amountB[:])
	var assetB [32]byte
	asset.FillBytes(assetB[:])
	pt := append(amountB[:], assetB[:]...)
	if blinding != nil {
		var blindingB [32]byte
		blinding.FillBytes(blindingB[:])
		pt = append(pt, blindingB[:]...)
	}
	return pt
}

func keySchedule(t *testing.T, sharedSecret *big.Int) (key [32]byte, nonce [12]byte) {
	t.Helper()
	siloed := mustHash(t, []*big.Int{domSepSilo, sharedSecret})
	keyLo := mustHash(t, []*big.Int{domSepKey, siloed})
	keyHi := mustHash(t, []*big.Int{domSepKey1, siloed})
	var keyLoB, keyHiB [32]byte
	keyLo.FillBytes(keyLoB[:])
	keyHi.FillBytes(keyHiB[:])
	copy(key[0:16], keyHiB[16:32])
	copy(key[16:32], keyLoB[16:32])

	nonceRaw := mustHash(t, []*big.Int{domSepNonce, siloed})
	var nonceB [32]byte
	nonceRaw.FillBytes(nonceB[:])
	copy(nonce[:], nonceB[20:32])
	return key, nonce
}

// ctrEncrypt matches aes/ctr.go CTREncrypt: J0 = nonce||0x00000001, the counter
// is incremented before the first block, so encryption starts at nonce||2.
func ctrEncrypt(t *testing.T, key [32]byte, nonce [12]byte, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	var iv [16]byte
	copy(iv[:12], nonce[:])
	iv[15] = 2
	out := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv[:]).XORKeyStream(out, plaintext)
	return out
}

func ringUtxo(u protocol.Utxo, treeID *big.Int) ringutils.Utxo {
	return ringutils.Utxo{
		Domain:          u.Domain,
		TreeID:          treeID,
		OwnerHash:       u.Owner,
		Asset:           u.Asset,
		Amount:          u.Amount,
		Blinding:        u.Blinding,
		ProgramDataHash: u.DataHash,
		RingDataHash:    u.RingDataHash,
		RingProgramID:   u.RingProgramID,
	}
}

func splitU128(v *big.Int) (lo, hi *big.Int) {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	lo = new(big.Int).And(v, mask)
	hi = new(big.Int).Rsh(v, 128)
	return lo, hi
}

func pack32(b [32]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(b[0:31]), new(big.Int).SetBytes(b[31:32])
}

func pack33(b [33]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(b[0:31]), new(big.Int).SetBytes(b[31:33])
}

func packBytesBE(b []byte, bytesPerFE int) []*big.Int {
	var out []*big.Int
	for off := 0; off < len(b); off += bytesPerFE {
		end := off + bytesPerFE
		if end > len(b) {
			end = len(b)
		}
		out = append(out, new(big.Int).SetBytes(b[off:end]))
	}
	return out
}

func hashChain(t *testing.T, in []*big.Int) *big.Int {
	t.Helper()
	h, err := protocol.HashChain(in)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func mustHash(t *testing.T, in []*big.Int) *big.Int {
	t.Helper()
	h, err := poseidon.Hash(in)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func leftPad32(v *big.Int) []byte {
	var b [32]byte
	v.FillBytes(b[:])
	return b[:]
}
