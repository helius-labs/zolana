package merge_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	merge "zolana/prover/circuits/spp_merge"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
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

func buildValidWitness(t *testing.T) *merge.Circuit {
	t.Helper()
	return buildWitness(t, false)
}

func buildWitness(t *testing.T, eddsa bool) *merge.Circuit {
	t.Helper()
	return buildDefaultWitness(t, mergeFixtureOptions{eddsa: eddsa})
}

type mergeFixtureRail uint8

const (
	defaultFixtureRail mergeFixtureRail = iota
	zoneFixtureRail
)

type mergeFixtureOptions struct {
	rail              mergeFixtureRail
	eddsa             bool
	zoneProgramID     *big.Int
	inputZoneData     []*big.Int
	outputZoneData    *big.Int
	userSigningPkHash *big.Int
	userViewingPkHash *big.Int
}

type mergeWitnessFixture struct {
	inputs []merge.Input
	output merge.Output

	asset               *big.Int
	ownerPkHash         *big.Int
	userNullifierPk     *big.Int
	userNullifierSecret *big.Int
	txViewingSk         *big.Int
	userViewingPubkey   [65]frontend.Variable
	public              mergeshared.CommonPublicInputs
	userSigningPkHash   *big.Int
	userViewingPkHash   *big.Int
	zoneProgramID       *big.Int
	publicInputHash     *big.Int
}

func buildDefaultWitness(t *testing.T, options mergeFixtureOptions) *merge.Circuit {
	t.Helper()
	options.rail = defaultFixtureRail
	return buildMergeFixture(t, options).defaultCircuit()
}

func buildZoneWitness(t *testing.T, zoneProgramID *big.Int) *merge.ZoneCircuit {
	t.Helper()
	return buildMergeFixture(t, mergeFixtureOptions{
		rail:           zoneFixtureRail,
		zoneProgramID:  zoneProgramID,
		inputZoneData:  []*big.Int{big.NewInt(0xD0), big.NewInt(0xD1)},
		outputZoneData: big.NewInt(0xD2),
	}).zoneCircuit()
}

func buildMergeFixture(t *testing.T, options mergeFixtureOptions) *mergeWitnessFixture {
	t.Helper()
	curve := elliptic.P256()

	// Owner identity: signing key (P256 or Solana) + shared nullifier secret.
	ownerSk := big.NewInt(11)
	ownerX, ownerY := curve.ScalarBaseMult(leftPad32(ownerSk))
	var ownerKeyHash *big.Int
	var err error
	if options.eddsa {
		var solanaPubkey [32]byte
		solanaPubkey[31] = 0x2a
		ownerKeyHash, err = protocol.SolanaPkField(solanaPubkey)
		if err != nil {
			t.Fatal(err)
		}
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
	zoneData := []*big.Int{big.NewInt(0), big.NewInt(0)}
	if options.inputZoneData != nil {
		if len(options.inputZoneData) != numReal {
			t.Fatalf("input zone data count: got %d want %d", len(options.inputZoneData), numReal)
		}
		zoneData = options.inputZoneData
	}
	outputZoneData := big.NewInt(0)
	if options.outputZoneData != nil {
		outputZoneData = options.outputZoneData
	}
	zoneProgramID := big.NewInt(0)
	if options.rail == zoneFixtureRail {
		if options.zoneProgramID == nil {
			t.Fatal("zone fixture requires a zone program ID")
		}
		zoneProgramID = options.zoneProgramID
	}

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
			ZoneDataHash:  zoneData[i],
			ZoneProgramID: zoneProgramID,
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
		ZoneDataHash:  outputZoneData,
		ZoneProgramID: zoneProgramID,
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
	userSigningPkHash := ownerKeyHash
	if options.userSigningPkHash != nil {
		userSigningPkHash = options.userSigningPkHash
	}
	userViewingPkHash := viewKeyHash
	if options.userViewingPkHash != nil {
		userViewingPkHash = options.userViewingPkHash
	}

	// Dummy slot: the DummyDomain sentinel with otherwise-empty content, matching
	// the padding leaf the client builds (owner/asset/secret all zero). The circuit
	// zeroes those fields for dummy slots and assembles the nullifier under a zero
	// secret, so the test mirrors that leaf here for the dummy public-input columns.
	dummyUtxo := protocol.Utxo{
		Domain:        big.NewInt(protocol.DummyDomain),
		Owner:         big.NewInt(0),
		Asset:         big.NewInt(0),
		Amount:        big.NewInt(0),
		Blinding:      big.NewInt(0),
		DataHash:      big.NewInt(0),
		ZoneDataHash:  big.NewInt(0),
		ZoneProgramID: big.NewInt(0),
	}
	dummyHash, err := protocol.UtxoHash(dummyUtxo)
	if err != nil {
		t.Fatal(err)
	}
	dummyNullifier, err := protocol.Nullifier(dummyHash, big.NewInt(0), big.NewInt(0))
	if err != nil {
		t.Fatal(err)
	}

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
			pubNullifiers[i] = dummyNullifier
			pubUtxoRoots[i] = stateRoot
			pubNfRoots[i] = nfRoot
		}
	}

	publicInputPreimage := []*big.Int{
		hashChain(t, pubNullifiers),
		outHash,
		hashChain(t, pubUtxoRoots),
		hashChain(t, pubNfRoots),
		privateTxHash,
		externalDataHash,
	}
	switch options.rail {
	case defaultFixtureRail:
		publicInputPreimage = append(
			publicInputPreimage,
			userSigningPkHash,
			userViewingPkHash,
			pkLo,
			pkHi,
			ctHash,
		)
	case zoneFixtureRail:
		publicInputPreimage = append(
			publicInputPreimage,
			pkLo,
			pkHi,
			ctHash,
			zoneProgramID,
		)
	default:
		t.Fatalf("unsupported merge fixture rail: %d", options.rail)
	}
	publicInputHash := hashChain(t, publicInputPreimage)

	inputs := mergeshared.NewInputs()
	public := mergeshared.NewCommonPublicInputs()
	var userViewingPubkey [65]frontend.Variable
	for i := 0; i < 65; i++ {
		userViewingPubkey[i] = big.NewInt(int64(userViewingUncompressed[i]))
	}
	public.ExternalDataHash = externalDataHash
	public.PrivateTxHash = privateTxHash
	public.OutputHash = outHash
	public.TxViewingPkLo = pkLo
	public.TxViewingPkHi = pkHi
	public.CtHash = ctHash

	for i := 0; i < merge.MergeInputs; i++ {
		in := &inputs[i]
		public.Nullifiers[i] = pubNullifiers[i]
		public.UtxoTreeRoots[i] = pubUtxoRoots[i]
		public.NullifierTreeRoots[i] = pubNfRoots[i]
		if i < numReal {
			in.Domain = big.NewInt(protocol.UtxoDomain)
			in.Amount = amounts[i]
			in.Blinding = blindings[i]
			in.ZoneDataHash = zoneData[i]
			fillPath(in.StatePathElements, stateProofs[uint64(i)].PathElements)
			in.StatePathIndex = big.NewInt(int64(stateProofs[uint64(i)].PathIndex))
			in.NullifierLowValue = nfWitnesses[i].LowValue
			in.NullifierNextValue = nfWitnesses[i].NextValue
			fillPath(in.NullifierLowPathElements, nfWitnesses[i].PathElements)
			in.NullifierLowPathIndex = big.NewInt(int64(nfWitnesses[i].LowIndex))
		} else {
			in.Domain = big.NewInt(protocol.DummyDomain)
			in.Amount = big.NewInt(0)
			in.Blinding = big.NewInt(0)
			in.ZoneDataHash = big.NewInt(0)
			zeroPath(in.StatePathElements)
			in.StatePathIndex = big.NewInt(0)
			in.NullifierLowValue = big.NewInt(0)
			in.NullifierNextValue = big.NewInt(0)
			zeroPath(in.NullifierLowPathElements)
			in.NullifierLowPathIndex = big.NewInt(0)
		}
	}

	return &mergeWitnessFixture{
		inputs:              inputs,
		output:              merge.Output{Blinding: outBlinding, ZoneDataHash: outputZoneData},
		asset:               asset,
		ownerPkHash:         ownerKeyHash,
		userNullifierPk:     userNullifierPk,
		userNullifierSecret: nullifierSecret,
		txViewingSk:         txViewingSk,
		userViewingPubkey:   userViewingPubkey,
		public:              public,
		userSigningPkHash:   userSigningPkHash,
		userViewingPkHash:   userViewingPkHash,
		zoneProgramID:       zoneProgramID,
		publicInputHash:     publicInputHash,
	}
}

func (f *mergeWitnessFixture) defaultCircuit() *merge.Circuit {
	assignment := merge.NewMergeCircuit()
	assignment.Inputs = f.inputs
	assignment.Output = f.output
	assignment.Asset = f.asset
	assignment.OwnerPkHash = f.ownerPkHash
	assignment.UserNullifierPk = f.userNullifierPk
	assignment.UserNullifierSecret = f.userNullifierSecret
	assignment.TxViewingSk = f.txViewingSk
	assignment.UserViewingPubkey = f.userViewingPubkey
	assignment.CommonPublicInputs = f.public
	assignment.UserSigningPkHash = f.userSigningPkHash
	assignment.UserViewingPkHash = f.userViewingPkHash
	assignment.PublicInputHash = f.publicInputHash
	return assignment
}

func (f *mergeWitnessFixture) zoneCircuit() *merge.ZoneCircuit {
	assignment := merge.NewMergeZoneCircuit()
	assignment.Inputs = f.inputs
	assignment.Output = f.output
	assignment.Asset = f.asset
	assignment.OwnerPkHash = f.ownerPkHash
	assignment.UserNullifierPk = f.userNullifierPk
	assignment.UserNullifierSecret = f.userNullifierSecret
	assignment.TxViewingSk = f.txViewingSk
	assignment.UserViewingPubkey = f.userViewingPubkey
	assignment.CommonPublicInputs = f.public
	assignment.ZoneProgramID = f.zoneProgramID
	assignment.PublicInputHash = f.publicInputHash
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
	key, nonce := keySchedule(t, sharedSecret, []byte(merge.MergeKDFInfo))

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
