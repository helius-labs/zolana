package merge_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"

	merge "zolana/prover/circuits/spp_merge"
	transaction "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover-test/poseidon"
	"zolana/prover/prover-test/spp/protocol"
)

// Domain separators, mirroring circuits/verifiable-encryption/poseidon_kdf.go.
var (
	domSepSharedSecret = big.NewInt(0x544d5353) // "TMSS"
	domSepSilo         = big.NewInt(0x544d5349) // "TMSI"
	domSepKey          = big.NewInt(0x544d534b) // "TMSK"
	domSepKey1         = big.NewInt(0x544d534c) // "TMSL" = DomSepKey + 1
	domSepNonce        = big.NewInt(0x544d534e) // "TMSN"
)

var mergeInfo = []byte("TSPP/merge")

// TestMergeCircuitProves checks the valid witness satisfies every constraint via
// the gnark test engine. The off-circuit encryption host below mirrors
// circuits/verifiable-encryption byte-for-byte, so a passing run proves the
// in-circuit and host KDF/AES-CTR agree.
func TestMergeCircuitProves(t *testing.T) {
	assignment := buildValidWitness(t)
	if err := test.IsSolved(merge.NewMergeCircuit(), assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("merge witness not solved: %v", err)
	}
}

// TestMergeCircuitProvesEddsaOwner checks a Solana-owned merge: the owner
// identity comes from a SolanaPkField witnessed in OwnerPkHash, and the
// P256 point is a discarded dummy. The rail select must accept it.
func TestMergeCircuitProvesEddsaOwner(t *testing.T) {
	assignment := buildWitness(t, true)
	if err := test.IsSolved(merge.NewMergeCircuit(), assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("eddsa merge witness not solved: %v", err)
	}
}

// TestMergeCircuitRejectsEddsaOwnerMismatch keeps the Solana-owned inputs but
// flips OwnerPkHash so the recomputed user_owner_hash no longer matches the
// input owners; ownership uniformity must fail.
func TestMergeCircuitRejectsEddsaOwnerMismatch(t *testing.T) {
	a := buildWitness(t, true)
	a.OwnerPkHash = big.NewInt(0xBADBAD)
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected eddsa ownership-uniformity failure, got solved")
	}
}

// TestMergeCircuitRejectsBadValueConservation breaks sum(inputs) == output by
// inflating the output amount; the output_utxo_hash is recomputed so only the
// conservation check fails.
func TestMergeCircuitRejectsBadValueConservation(t *testing.T) {
	a := buildValidWitness(t)
	a.Output.Utxo.Amount = big.NewInt(999)
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected value-conservation failure, got solved")
	}
}

// TestMergeCircuitRejectsTamperedCiphertext flips a public-input-hash input
// (external data hash) without re-deriving PublicInputHash; the final check fails.
func TestMergeCircuitRejectsTamperedPublicInput(t *testing.T) {
	a := buildValidWitness(t)
	a.ExternalDataHash = big.NewInt(0xDEAD)
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected public-input-hash failure, got solved")
	}
}

// TestMergeCircuitRejectsWrongOwner breaks ownership uniformity: an input UTXO
// owned by a different owner hash than user_owner_hash.
func TestMergeCircuitRejectsWrongOwner(t *testing.T) {
	a := buildValidWitness(t)
	a.Inputs[0].Utxo.Owner = big.NewInt(0xBADBAD)
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected ownership-uniformity failure, got solved")
	}
}

func buildValidWitness(t *testing.T) *merge.Circuit {
	t.Helper()
	return buildWitness(t, false)
}

// buildWitness assembles a solved 2-real-input merge witness. With eddsa set the
// owner is a Solana (ed25519) signer: ownerKeyHash is a SolanaPkField, the
// circuit's P256 witness is a discarded dummy point, and OwnerPkHash drives
// the rail select. With eddsa false the owner is a P256 signer (OwnerPkHash
// stays 0).
func buildWitness(t *testing.T, eddsa bool) *merge.Circuit {
	t.Helper()
	curve := elliptic.P256()

	// Owner identity: signing key (P256 or Solana) + shared nullifier secret.
	ownerSk := big.NewInt(11)
	ownerX, ownerY := curve.ScalarBaseMult(leftPad32(ownerSk))
	ownerPkHash := big.NewInt(0)
	var ownerKeyHash *big.Int
	var err error
	if eddsa {
		var solanaPubkey [32]byte
		solanaPubkey[31] = 0x2a
		ownerKeyHash, err = protocol.SolanaPkField(solanaPubkey)
		if err != nil {
			t.Fatal(err)
		}
		ownerPkHash = ownerKeyHash
	} else {
		ownerComp := elliptic.MarshalCompressed(curve, ownerX, ownerY)
		ownerKeyHash, err = protocol.OwnerPkField(ownerComp)
		if err != nil {
			t.Fatal(err)
		}
	}
	nullifierSecret := big.NewInt(19)
	userNullifierPk, err := protocol.NullifierPk(nullifierSecret)
	if err != nil {
		t.Fatal(err)
	}
	userOwnerHash, err := protocol.OwnerHash(ownerKeyHash, userNullifierPk)
	if err != nil {
		t.Fatal(err)
	}

	// Owner viewing key (recipient of the verifiable encryption).
	viewSk := big.NewInt(7)
	viewX, viewY := curve.ScalarBaseMult(leftPad32(viewSk))
	userViewingUncompressed := elliptic.Marshal(curve, viewX, viewY) // 0x04 || x || y
	viewKeyHash, err := protocol.P256PkField(elliptic.MarshalCompressed(curve, viewX, viewY))
	if err != nil {
		t.Fatal(err)
	}

	// Ephemeral tx viewing key.
	txViewingSk := big.NewInt(123456789)

	asset := big.NewInt(1)
	const numReal = 2
	amounts := []*big.Int{big.NewInt(5), big.NewInt(7)}
	blindings := []*big.Int{big.NewInt(0x1111), big.NewInt(0x2222)}

	// Real input UTXOs and their state-tree leaves.
	inUtxos := make([]protocol.Utxo, numReal)
	inHashes := make([]*big.Int, numReal)
	stateEntries := map[uint64]*big.Int{}
	for i := 0; i < numReal; i++ {
		inUtxos[i] = protocol.Utxo{
			Domain:        big.NewInt(protocol.UtxoDomain),
			Owner:         userOwnerHash,
			Asset:         asset,
			Amount:        amounts[i],
			Blinding:      blindings[i],
			DataHash:      big.NewInt(0),
			ZoneDataHash:  big.NewInt(0),
			ZoneProgramID: big.NewInt(0),
		}
		h, err := protocol.UtxoHash(inUtxos[i])
		if err != nil {
			t.Fatal(err)
		}
		inHashes[i] = h
		stateEntries[uint64(i)] = h
	}
	stateRoot, stateProofs, err := protocol.BuildSparseStateTree(stateEntries)
	if err != nil {
		t.Fatal(err)
	}

	// Empty nullifier tree: every real nullifier is bracketed by the sentinel.
	nfTree, err := protocol.NewNullifierTree()
	if err != nil {
		t.Fatal(err)
	}
	nfRoot := nfTree.Root()
	nullifiers := make([]*big.Int, numReal)
	nfWitnesses := make([]protocol.NonInclusionWitness, numReal)
	for i := 0; i < numReal; i++ {
		nf, err := protocol.Nullifier(inHashes[i], blindings[i], nullifierSecret)
		if err != nil {
			t.Fatal(err)
		}
		nullifiers[i] = nf
		w, err := nfTree.NonInclusionWitness(nf)
		if err != nil {
			t.Fatal(err)
		}
		nfWitnesses[i] = w
	}

	// Merged output.
	outAmount := new(big.Int).Add(amounts[0], amounts[1])
	outBlinding := big.NewInt(0x3333)
	outUtxo := protocol.Utxo{
		Domain:        big.NewInt(protocol.UtxoDomain),
		Owner:         userOwnerHash,
		Asset:         asset,
		Amount:        outAmount,
		Blinding:      outBlinding,
		DataHash:      big.NewInt(0),
		ZoneDataHash:  big.NewInt(0),
		ZoneProgramID: big.NewInt(0),
	}
	outHash, err := protocol.UtxoHash(outUtxo)
	if err != nil {
		t.Fatal(err)
	}

	externalDataHash := big.NewInt(0xABCDEF)

	// private_tx_hash over the input/output hash chains (dummies contribute 0).
	inputHashChainInputs := make([]*big.Int, merge.MergeInputs)
	for i := 0; i < merge.MergeInputs; i++ {
		if i < numReal {
			inputHashChainInputs[i] = inHashes[i]
		} else {
			inputHashChainInputs[i] = big.NewInt(0)
		}
	}
	addressHashes := make([]*big.Int, merge.MergeInputs)
	for i := range addressHashes {
		addressHashes[i] = big.NewInt(0)
	}
	privateTxHash, err := protocol.PrivateTxHash(inputHashChainInputs, []*big.Int{outHash}, addressHashes, externalDataHash)
	if err != nil {
		t.Fatal(err)
	}

	// Off-circuit verifiable encryption of (amount || asset || blinding).
	ctHash, txViewingPkComp := encryptMerge(t, curve, txViewingSk, viewX, viewY, outUtxo)
	pkLo, pkHi := pack33(txViewingPkComp)

	// Public columns (real + dummy), reused verbatim in the public input hash.
	pubNullifiers := make([]*big.Int, merge.MergeInputs)
	pubUtxoRoots := make([]*big.Int, merge.MergeInputs)
	pubNfRoots := make([]*big.Int, merge.MergeInputs)
	for i := 0; i < merge.MergeInputs; i++ {
		if i < numReal {
			pubNullifiers[i] = nullifiers[i]
			pubUtxoRoots[i] = stateRoot
			pubNfRoots[i] = nfRoot
		} else {
			pubNullifiers[i] = big.NewInt(int64(1000 + i)) // dummy nullifier, unpinned
			pubUtxoRoots[i] = stateRoot
			pubNfRoots[i] = nfRoot
		}
	}

	publicInputHash := hashChain(t, []*big.Int{
		hashChain(t, pubNullifiers),
		outHash,
		hashChain(t, pubUtxoRoots),
		hashChain(t, pubNfRoots),
		privateTxHash,
		externalDataHash,
		ownerKeyHash,
		viewKeyHash,
		pkLo, pkHi,
		ctHash,
	})

	// Assemble the witness assignment.
	assignment := merge.NewMergeCircuit()
	assignment.P256Pub = transaction.P256PublicKey{
		X: emulated.ValueOf[emulated.P256Fp](ownerX),
		Y: emulated.ValueOf[emulated.P256Fp](ownerY),
	}
	assignment.OwnerPkHash = ownerPkHash
	assignment.UserNullifierPk = userNullifierPk
	assignment.UserNullifierSecret = nullifierSecret
	assignment.TxViewingSk = txViewingSk
	for i := 0; i < 65; i++ {
		assignment.UserViewingPubkey[i] = big.NewInt(int64(userViewingUncompressed[i]))
	}
	assignment.ExternalDataHash = externalDataHash
	assignment.PrivateTxHash = privateTxHash
	assignment.PublicInputHash = publicInputHash

	for i := 0; i < merge.MergeInputs; i++ {
		in := &assignment.Inputs[i]
		if i < numReal {
			in.IsDummy = 0
			in.Utxo = utxoFields(inUtxos[i])
			fillPath(in.StatePathElements, stateProofs[uint64(i)].PathElements)
			in.StatePathIndex = big.NewInt(int64(stateProofs[uint64(i)].PathIndex))
			in.NullifierLowValue = nfWitnesses[i].LowValue
			in.NullifierNextValue = nfWitnesses[i].NextValue
			fillPath(in.NullifierLowPathElements, nfWitnesses[i].PathElements)
			in.NullifierLowPathIndex = big.NewInt(int64(nfWitnesses[i].LowIndex))
			in.UtxoTreeRoot = stateRoot
			in.NullifierTreeRoot = nfRoot
			in.Nullifier = nullifiers[i]
		} else {
			in.IsDummy = 1
			in.Utxo = utxoFields(protocol.Utxo{
				Domain:        big.NewInt(0),
				Owner:         big.NewInt(0),
				Asset:         big.NewInt(0),
				Amount:        big.NewInt(0),
				Blinding:      big.NewInt(0),
				DataHash:      big.NewInt(0),
				ZoneDataHash:  big.NewInt(0),
				ZoneProgramID: big.NewInt(0),
			})
			zeroPath(in.StatePathElements)
			in.StatePathIndex = big.NewInt(0)
			in.NullifierLowValue = big.NewInt(0)
			in.NullifierNextValue = big.NewInt(0)
			zeroPath(in.NullifierLowPathElements)
			in.NullifierLowPathIndex = big.NewInt(0)
			in.UtxoTreeRoot = pubUtxoRoots[i]
			in.NullifierTreeRoot = pubNfRoots[i]
			in.Nullifier = pubNullifiers[i]
		}
	}
	assignment.Output = merge.Output{Utxo: utxoFields(outUtxo), Hash: outHash}

	return assignment
}

// encryptMerge mirrors merge/encryption.go off-circuit and returns the Poseidon
// ciphertext hash and the compressed tx_viewing_pk.
func encryptMerge(t *testing.T, curve elliptic.Curve, txViewingSk, viewX, viewY *big.Int, out protocol.Utxo) (*big.Int, [33]byte) {
	t.Helper()
	skBytes := leftPad32(txViewingSk)

	// tx_viewing_pk = sk*G (keypair consistency).
	pkX, pkY := curve.ScalarBaseMult(skBytes)
	var txViewingPkComp [33]byte
	copy(txViewingPkComp[:], elliptic.MarshalCompressed(curve, pkX, pkY))

	// ECDH x-coordinate.
	dhX, _ := curve.ScalarMult(viewX, viewY, skBytes)
	var dh [32]byte
	dhX.FillBytes(dh[:])

	var rpkComp [33]byte
	copy(rpkComp[:], elliptic.MarshalCompressed(curve, viewX, viewY))

	sharedSecret := deriveSharedSecret(t, dh, txViewingPkComp, rpkComp)
	key, nonce := keySchedule(t, sharedSecret, mergeInfo)

	plaintext := mergePlaintext(out)
	ciphertext := ctrEncrypt(t, key, nonce, plaintext)

	packed := packBytesBE(ciphertext, 16)
	ctHash, err := poseidon.Hash(packed)
	if err != nil {
		t.Fatal(err)
	}
	return ctHash, txViewingPkComp
}

func deriveSharedSecret(t *testing.T, dh [32]byte, ephComp, rpkComp [33]byte) *big.Int {
	t.Helper()
	dhLo, dhHi := pack32(dh)
	ephLo, ephHi := pack33(ephComp)
	rpkLo, rpkHi := pack33(rpkComp)
	h, err := poseidon.Hash([]*big.Int{domSepSharedSecret, dhLo, dhHi, ephLo, ephHi, rpkLo, rpkHi})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func keySchedule(t *testing.T, sharedSecret *big.Int, info []byte) (key [32]byte, nonce [12]byte) {
	t.Helper()
	infoLo, infoHi := packInfo(info)
	siloed, err := poseidon.Hash([]*big.Int{domSepSilo, sharedSecret, infoLo, infoHi})
	if err != nil {
		t.Fatal(err)
	}
	keyLo, err := poseidon.Hash([]*big.Int{domSepKey, siloed})
	if err != nil {
		t.Fatal(err)
	}
	keyHi, err := poseidon.Hash([]*big.Int{domSepKey1, siloed})
	if err != nil {
		t.Fatal(err)
	}
	var keyLoB, keyHiB [32]byte
	keyLo.FillBytes(keyLoB[:])
	keyHi.FillBytes(keyHiB[:])
	copy(key[0:16], keyHiB[16:32])
	copy(key[16:32], keyLoB[16:32])

	nonceRaw, err := poseidon.Hash([]*big.Int{domSepNonce, siloed})
	if err != nil {
		t.Fatal(err)
	}
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

func mergePlaintext(out protocol.Utxo) []byte {
	pt := make([]byte, 0, merge.MergePlaintextLen)
	var amount [8]byte
	out.Amount.FillBytes(amount[:])
	var asset [32]byte
	out.Asset.FillBytes(asset[:])
	var blinding [31]byte
	out.Blinding.FillBytes(blinding[:])
	pt = append(pt, amount[:]...)
	pt = append(pt, asset[:]...)
	pt = append(pt, blinding[:]...)
	return pt
}

func pack32(b [32]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(b[0:31]), new(big.Int).SetBytes(b[31:32])
}

func pack33(b [33]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(b[0:31]), new(big.Int).SetBytes(b[31:33])
}

func packInfo(info []byte) (lo, hi *big.Int) {
	split := len(info)
	if split > 31 {
		split = 31
	}
	lo = new(big.Int).Lsh(big.NewInt(int64(len(info))), 8*31)
	lo.Add(lo, new(big.Int).SetBytes(info[:split]))
	hi = new(big.Int).SetBytes(info[split:])
	return lo, hi
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

func utxoFields(u protocol.Utxo) transaction.UtxoCircuitFields {
	return transaction.UtxoCircuitFields{
		Domain:        u.Domain,
		Owner:         u.Owner,
		Asset:         u.Asset,
		Amount:        u.Amount,
		Blinding:      u.Blinding,
		DataHash:      u.DataHash,
		ZoneDataHash:  u.ZoneDataHash,
		ZoneProgramID: u.ZoneProgramID,
	}
}

func fillPath(dst []frontend.Variable, src []*big.Int) {
	for i := range dst {
		dst[i] = src[i]
	}
}

func zeroPath(dst []frontend.Variable) {
	for i := range dst {
		dst[i] = big.NewInt(0)
	}
}

func leftPad32(v *big.Int) []byte {
	var b [32]byte
	v.FillBytes(b[:])
	return b[:]
}
