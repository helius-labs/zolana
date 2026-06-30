package transaction_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
	. "zolana/prover/circuits/spp_transaction"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func TestCircuitCompilesForSupportedShapes(t *testing.T) {
	for _, shape := range protocol.SupportedShapes {
		shape := shape
		t.Run(shape.String(), func(t *testing.T) {
			circuit := MustNewCircuit(Shape(shape))
			if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300)); err != nil {
				t.Fatalf("compile SPP circuit %s: %v", shape, err)
			}
		})
	}
}

func TestCircuitProvesForSupportedShapes(t *testing.T) {
	for _, shape := range protocol.SupportedShapes {
		shape := shape
		t.Run(shape.String(), func(t *testing.T) {
			assert := test.NewAssert(t)
			circuit := MustNewCircuit(Shape(shape))
			assignment := buildCircuitAssignment(t, shape)

			assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
			assert.ProverSucceeded(
				circuit,
				assignment,
				test.WithBackends(backend.GROTH16),
				test.WithCurves(ecc.BN254),
				test.NoSerializationChecks(),
			)
		})
	}
}

func MustNewCircuit(shape Shape) *Circuit {
	circuit, err := NewTransferP256ZoneCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

// MustNewSolanaCircuit builds the Solana-only circuit and panics on error.
func MustNewSolanaCircuit(shape Shape) *Circuit {
	circuit, err := NewTransferZoneCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

func buildCircuitAssignment(t testing.TB, shape protocol.Shape) *Circuit {
	t.Helper()

	inputUtxos, outputUtxos := defaultBalancedUtxos(t, shape)
	return buildCircuitAssignmentFromUtxos(
		t,
		shape,
		inputUtxos,
		outputUtxos,
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)
}

func buildCircuitAssignmentFromUtxos(
	t testing.TB,
	shape protocol.Shape,
	inputUtxos []protocol.Utxo,
	outputUtxos []protocol.Utxo,
	publicSolAmount *big.Int,
	publicSplAmount *big.Int,
	publicSplAssetPubkey *big.Int,
) *Circuit {
	t.Helper()
	return buildCircuitAssignmentExact(
		t,
		shape,
		inputUtxos,
		outputUtxos,
		publicSolAmount,
		publicSplAmount,
		publicSplAssetPubkey,
	)
}

func buildCircuitAssignmentExact(
	t testing.TB,
	shape protocol.Shape,
	inputUtxos []protocol.Utxo,
	outputUtxos []protocol.Utxo,
	publicSolAmount *big.Int,
	publicSplAmount *big.Int,
	publicSplAssetPubkey *big.Int,
) *Circuit {
	t.Helper()
	if len(inputUtxos) != shape.NInputs {
		t.Fatalf("input UTXO count mismatch: got %d want %d", len(inputUtxos), shape.NInputs)
	}
	if len(outputUtxos) != shape.NOutputs {
		t.Fatalf("output UTXO count mismatch: got %d want %d", len(outputUtxos), shape.NOutputs)
	}

	nullifierSecrets := make([]*big.Int, shape.NInputs)
	inputOwnerPkHashes := make([]*big.Int, shape.NInputs)
	inputCircuitUtxos := make([]UtxoCircuitFields, shape.NInputs)
	inputHashes := make([]*big.Int, shape.NInputs)
	nullifiers := make([]frontend.Variable, shape.NInputs)
	stateEntries := make(map[uint64]*big.Int)
	stateLeafIndices := make([]uint64, shape.NInputs)

	for i := 0; i < shape.NInputs; i++ {
		utxo := inputUtxos[i]
		nullifierSecrets[i] = spptest.Fe(99)
		inputOwnerPkHashes[i] = testSolanaPkField(t)
		inputCircuitUtxos[i] = fieldsFromUtxo(utxo)
		inputHash := spptest.MustUtxoHash(t, utxo)
		inputHashes[i] = inputHash
		nullifier := spptest.MustNullifier(t, inputHash, utxo.Blinding, nullifierSecrets[i])
		nullifiers[i] = nullifier
		stateLeafIndices[i] = defaultStateLeafIndex(i)
		stateEntries[stateLeafIndices[i]] = inputHash
	}
	stateRoot, stateProofs := spptest.MustBuildSparseStateTree(t, stateEntries)
	statePathElementsVars := make([][]frontend.Variable, shape.NInputs)
	statePathIndexVars := make([]frontend.Variable, shape.NInputs)
	for i := 0; i < shape.NInputs; i++ {
		statePathElementsVars[i] = spptest.ZeroVariables(protocol.StateTreeHeight)
		proof := stateProofs[stateLeafIndices[i]]
		fillStateProofElements(statePathElementsVars[i], proof.PathElements)
		statePathIndexVars[i] = new(big.Int).SetUint64(proof.PathIndex)
	}

	nullifierTree := spptest.MustNewNullifierTree(t)
	nfLowValueVars := make([]frontend.Variable, shape.NInputs)
	nfNextValueVars := make([]frontend.Variable, shape.NInputs)
	nfLowPathElementVars := make([][]frontend.Variable, shape.NInputs)
	nfLowPathIndexVars := make([]frontend.Variable, shape.NInputs)
	for i := 0; i < shape.NInputs; i++ {
		nfLowValueVars[i] = spptest.Fe(0)
		nfNextValueVars[i] = spptest.Fe(0)
		nfLowPathElementVars[i] = spptest.ZeroVariables(protocol.NullifierTreeHeight)
		witness := spptest.MustNonInclusion(t, nullifierTree, spptest.AsBigInt(nullifiers[i]))
		nfLowValueVars[i] = witness.LowValue
		nfNextValueVars[i] = witness.NextValue
		fillStateProofElements(nfLowPathElementVars[i], witness.PathElements)
		nfLowPathIndexVars[i] = new(big.Int).SetUint64(witness.LowIndex)
	}
	utxoTreeRoots := spptest.RepeatBigInt(stateRoot, shape.NInputs)
	nullifierTreeRoots := spptest.RepeatBigInt(nullifierTree.Root(), shape.NInputs)

	outputCircuitUtxos := make([]UtxoCircuitFields, shape.NOutputs)
	OutputHashes := make([]*big.Int, shape.NOutputs)
	outputHashVariables := make([]frontend.Variable, shape.NOutputs)
	for i := 0; i < shape.NOutputs; i++ {
		utxo := outputUtxos[i]
		outputCircuitUtxos[i] = fieldsFromUtxo(utxo)
		outputHash := spptest.MustUtxoHash(t, utxo)
		OutputHashes[i] = outputHash
		outputHashVariables[i] = outputHash
	}

	externalDataHash := spptest.Fe(300)
	privateTxHash := spptest.MustPrivateTxHash(t, inputHashes, OutputHashes, noAddressHashes(shape.NInputs), externalDataHash)
	p256MessageDigest := spptest.MustP256MessageDigest(t, privateTxHash)
	p256MessageLow, p256MessageHigh := protocol.P256MessageLimbs(p256MessageDigest)
	p256MessageHashField := spptest.MustP256FieldFromLimbs(t, p256MessageLow, p256MessageHigh)
	p256Pub, p256Sig, err := spptest.UnusedP256Witness(p256MessageDigest[:])
	if err != nil {
		t.Fatalf("unused P256 witness: %v", err)
	}
	payerPubkeyHash := testPayerPubkeyHash()

	publicInputs := protocol.PublicInputs{
		Nullifiers:           spptest.ToBigInts(nullifiers),
		OutputUtxoHashes:     OutputHashes,
		UtxoTreeRoots:        utxoTreeRoots,
		NullifierTreeRoots:   nullifierTreeRoots,
		PrivateTxHash:        privateTxHash,
		P256MessageHash:      p256MessageHashField,
		ExternalDataHash:     externalDataHash,
		PublicSolAmount:      protocol.SignedToField(publicSolAmount),
		PublicSplAmount:      protocol.SignedToField(publicSplAmount),
		PublicSplAssetPubkey: publicSplAssetPubkey,
		ZoneProgramID:        spptest.Fe(0),
		PayerPubkeyHash:      payerPubkeyHash,
		InputOwnerPkHashes:   inputOwnerPkHashes,
	}
	publicInputHashValue, err := protocol.PublicInputHash(publicInputs)
	publicInputHash := spptest.MustHash(t, publicInputHashValue, err)

	inputs := make([]Input, shape.NInputs)
	for i := 0; i < shape.NInputs; i++ {
		inputs[i] = Input{
			Utxo:                     inputCircuitUtxos[i],
			IsDummy:                  spptest.Fe(0),
			StatePathElements:        statePathElementsVars[i],
			StatePathIndex:           statePathIndexVars[i],
			NullifierLowValue:        nfLowValueVars[i],
			NullifierNextValue:       nfNextValueVars[i],
			NullifierLowPathElements: nfLowPathElementVars[i],
			NullifierLowPathIndex:    nfLowPathIndexVars[i],
			UtxoTreeRoot:             utxoTreeRoots[i],
			NullifierTreeRoot:        nullifierTreeRoots[i],
			Nullifier:                nullifiers[i],
			OwnerPkHash:              inputOwnerPkHashes[i],
			NullifierSecret:          nullifierSecrets[i],
		}
	}
	outputs := make([]Output, shape.NOutputs)
	for i := 0; i < shape.NOutputs; i++ {
		outputs[i] = Output{
			Utxo:        outputCircuitUtxos[i],
			IsDummy:     spptest.Fe(0),
			Hash:        outputHashVariables[i],
			OwnerPkHash: spptest.Fe(0),
			NullifierPk: spptest.Fe(0),
		}
	}

	return &Circuit{
		Shape:                Shape(shape),
		Inputs:               inputs,
		Outputs:              outputs,
		ExternalDataHash:     externalDataHash,
		P256Pub:              p256Pub,
		P256Sig:              p256Sig,
		PrivateTxHash:        privateTxHash,
		P256MessageHashLow:   p256MessageLow,
		P256MessageHashHigh:  p256MessageHigh,
		P256SigningPkField:   spptest.Fe(0),
		PublicSolAmount:      publicInputs.PublicSolAmount,
		PublicSplAmount:      publicInputs.PublicSplAmount,
		PublicSplAssetPubkey: publicInputs.PublicSplAssetPubkey,
		ZoneProgramID:        publicInputs.ZoneProgramID,
		PayerPubkeyHash:      publicInputs.PayerPubkeyHash,
		PublicInputHash:      publicInputHash,
	}
}

func defaultStateLeafIndex(i int) uint64 {
	return uint64(17 + i)
}

func noAddressHashes(nInputs int) []*big.Int {
	return spptest.RepeatBigInt(spptest.Fe(0), nInputs)
}

func fillStateProofElements(pathElements []frontend.Variable, proofElements []*big.Int) {
	if len(pathElements) != len(proofElements) {
		panic("spp test: state path length mismatch")
	}
	for i := range proofElements {
		pathElements[i] = proofElements[i]
	}
}

func refreshPublicInputHash(t testing.TB, assignment *Circuit) {
	refreshPublicInputHashVariant(t, assignment, false, false)
}

func refreshPublicInputHashVariant(t testing.TB, assignment *Circuit, confidential, zoneAuthority bool) {
	t.Helper()
	publicInputs := protocol.PublicInputs{
		Nullifiers:         spptest.ToBigInts(assignment.InputNullifiers()),
		OutputUtxoHashes:   spptest.ToBigInts(assignment.OutputHashes()),
		UtxoTreeRoots:      spptest.ToBigInts(assignment.InputUtxoRoots()),
		NullifierTreeRoots: spptest.ToBigInts(assignment.InputNullifierTreeRoots()),
		PrivateTxHash:      spptest.AsBigInt(assignment.PrivateTxHash),
		P256MessageHash: spptest.MustP256FieldFromLimbs(
			t,
			spptest.AsBigInt(assignment.P256MessageHashLow),
			spptest.AsBigInt(assignment.P256MessageHashHigh),
		),
		ExternalDataHash:     spptest.AsBigInt(assignment.ExternalDataHash),
		PublicSolAmount:      spptest.AsBigInt(assignment.PublicSolAmount),
		PublicSplAmount:      spptest.AsBigInt(assignment.PublicSplAmount),
		PublicSplAssetPubkey: spptest.AsBigInt(assignment.PublicSplAssetPubkey),
		ZoneProgramID:        spptest.AsBigInt(assignment.ZoneProgramID),
		PayerPubkeyHash:      spptest.AsBigInt(assignment.PayerPubkeyHash),
		InputOwnerPkHashes:   spptest.ToBigInts(assignment.InputOwnerPkHashes()),
		Confidential:         confidential,
		ZoneAuthority:        zoneAuthority,
	}
	if confidential {
		publicInputs.OutputOwnerPkHashes = spptest.ToBigInts(assignment.OutputOwnerPkHashes())
		publicInputs.P256SigningPkField = spptest.AsBigInt(assignment.P256SigningPkField)
	}
	publicInputHashValue, err := protocol.PublicInputHash(publicInputs)
	assignment.PublicInputHash = spptest.MustHash(t, publicInputHashValue, err)
}

func defaultBalancedUtxos(t testing.TB, shape protocol.Shape) ([]protocol.Utxo, []protocol.Utxo) {
	t.Helper()

	asset := spptest.Fe(7)
	inputs := make([]protocol.Utxo, shape.NInputs)
	total := int64(0)
	for i := 0; i < shape.NInputs; i++ {
		amount := int64(100 + i*10)
		inputs[i] = sampleUtxoWithAssetAndAmount(10+i*10, asset, spptest.Fe(amount))
		total += amount
	}
	outputs := make([]protocol.Utxo, shape.NOutputs)
	remaining := total
	for i := 0; i < shape.NOutputs; i++ {
		amount := remaining / int64(shape.NOutputs-i)
		remaining -= amount
		outputs[i] = sampleUtxoWithAssetAndAmount(100+i*10, asset, spptest.Fe(amount))
	}
	return inputs, outputs
}

func sampleUtxoWithAssetAndAmount(base int, asset, amount *big.Int) protocol.Utxo {
	utxo := sampleUtxo(base)
	utxo.Asset = new(big.Int).Set(asset)
	utxo.Amount = new(big.Int).Set(amount)
	return utxo
}

func twoOutputUtxos(output protocol.Utxo) []protocol.Utxo {
	return []protocol.Utxo{
		output,
		sampleUtxoWithAssetAndAmount(110, output.Asset, spptest.Fe(0)),
	}
}

func sampleUtxo(base int) protocol.Utxo {
	return protocol.Utxo{
		Domain:        spptest.Fe(protocol.UtxoDomain),
		Owner:         testOwnerHashForNullifierSecret(spptest.Fe(99)),
		Asset:         spptest.Fe(int64(base + 3)),
		Amount:        spptest.Fe(int64(base + 4)),
		Blinding:      spptest.Fe(int64(base + 5)),
		DataHash:      spptest.Fe(0),
		ZoneDataHash:  spptest.Fe(0),
		ZoneProgramID: spptest.Fe(0),
	}
}

func rewriteSingleInputAsP256(t testing.TB, assignment *Circuit, ownerPriv, signingPriv *ecdsa.PrivateKey) {
	t.Helper()
	if len(assignment.Inputs) != 1 {
		t.Fatalf("rewriteSingleInputAsP256 expects one input, got %d", len(assignment.Inputs))
	}
	rewriteInputAsP256(t, assignment, 0, ownerPriv, signingPriv)
}

func rewriteInputAsP256(
	t testing.TB,
	assignment *Circuit,
	inputIndex int,
	ownerPriv *ecdsa.PrivateKey,
	signingPriv *ecdsa.PrivateKey,
) {
	t.Helper()
	if inputIndex < 0 || inputIndex >= len(assignment.Inputs) {
		t.Fatalf("P256 input index %d out of range", inputIndex)
	}

	nullifierSecret := spptest.AsBigInt(assignment.Inputs[inputIndex].NullifierSecret)
	nullifierPk := spptest.MustNullifierPk(t, nullifierSecret)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), ownerPriv.PublicKey.X, ownerPriv.PublicKey.Y)
	ownerKeyHash, err := protocol.OwnerPkField(compressed)
	if err != nil {
		t.Fatalf("P256 owner key hash: %v", err)
	}
	owner, err := protocol.OwnerHash(ownerKeyHash, nullifierPk)
	if err != nil {
		t.Fatalf("P256 owner hash: %v", err)
	}
	assignment.Inputs[inputIndex].Utxo.Owner = owner
	assignment.Inputs[inputIndex].OwnerPkHash = spptest.Fe(0)

	rebuildAfterOwnerChange(t, assignment)
	msg := spptest.MustP256MessageDigest(t, spptest.AsBigInt(assignment.PrivateTxHash))
	r, s, err := ecdsa.Sign(rand.Reader, signingPriv, msg[:])
	if err != nil {
		t.Fatalf("sign P256 private tx hash: %v", err)
	}
	assignment.P256Pub = spptest.P256PubkeyAssignment(ownerPriv)
	assignment.P256Sig = P256Signature{
		R: emulated.ValueOf[emulated.P256Fr](r),
		S: emulated.ValueOf[emulated.P256Fr](s),
	}
}

func rewriteInputAsSolanaOwner(
	t testing.TB,
	assignment *Circuit,
	inputIndex int,
	seed byte,
	nullifierSecret *big.Int,
) {
	t.Helper()
	if inputIndex < 0 || inputIndex >= len(assignment.Inputs) {
		t.Fatalf("Solana owner input index %d out of range", inputIndex)
	}
	pkField := testSolanaPkFieldSeed(t, seed)
	nullifierPk := spptest.MustNullifierPk(t, nullifierSecret)
	owner, err := protocol.OwnerHash(pkField, nullifierPk)
	if err != nil {
		t.Fatalf("owner hash: %v", err)
	}
	assignment.Inputs[inputIndex].Utxo.Owner = owner
	assignment.Inputs[inputIndex].OwnerPkHash = pkField
	assignment.Inputs[inputIndex].NullifierSecret = nullifierSecret
	rebuildAfterOwnerChange(t, assignment)
}

func rebuildAfterOwnerChange(t testing.TB, assignment *Circuit) {
	t.Helper()
	inputHashes := make([]*big.Int, len(assignment.Inputs))
	stateEntries := make(map[uint64]*big.Int, len(assignment.Inputs))
	for i := range assignment.Inputs {
		inputHash := spptest.MustUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[i].Utxo))
		inputHashes[i] = inputHash
		stateEntries[defaultStateLeafIndex(i)] = inputHash
	}
	stateRoot, stateProofs := spptest.MustBuildSparseStateTree(t, stateEntries)
	nullifierTree := spptest.MustNewNullifierTree(t)
	for i := range assignment.Inputs {
		stateProof := stateProofs[defaultStateLeafIndex(i)]
		fillStateProofElements(assignment.Inputs[i].StatePathElements, stateProof.PathElements)
		assignment.Inputs[i].StatePathIndex = new(big.Int).SetUint64(stateProof.PathIndex)
		assignment.Inputs[i].UtxoTreeRoot = stateRoot

		nullifier := spptest.MustNullifier(
			t,
			inputHashes[i],
			spptest.AsBigInt(assignment.Inputs[i].Utxo.Blinding),
			spptest.AsBigInt(assignment.Inputs[i].NullifierSecret),
		)
		assignment.Inputs[i].Nullifier = nullifier
		nfWitness := spptest.MustNonInclusion(t, nullifierTree, nullifier)
		assignment.Inputs[i].NullifierLowValue = nfWitness.LowValue
		assignment.Inputs[i].NullifierNextValue = nfWitness.NextValue
		fillStateProofElements(assignment.Inputs[i].NullifierLowPathElements, nfWitness.PathElements)
		assignment.Inputs[i].NullifierLowPathIndex = new(big.Int).SetUint64(nfWitness.LowIndex)
		assignment.Inputs[i].NullifierTreeRoot = nullifierTree.Root()
	}

	OutputHashes := spptest.ToBigInts(assignment.OutputHashes())
	privateTxHash := spptest.MustPrivateTxHash(
		t,
		inputHashes,
		OutputHashes,
		noAddressHashes(len(inputHashes)),
		spptest.AsBigInt(assignment.ExternalDataHash),
	)
	assignment.PrivateTxHash = privateTxHash
	assignment.P256MessageHashLow, assignment.P256MessageHashHigh = spptest.MustP256MessageLimbs(t, privateTxHash)
	refreshPublicInputHash(t, assignment)
}

func testOwnerHashForNullifierSecret(nullifierSecret *big.Int) *big.Int {
	nullifierPk, err := protocol.NullifierPk(nullifierSecret)
	if err != nil {
		panic(err)
	}
	owner, err := protocol.OwnerHash(testSolanaPkField(nil), nullifierPk)
	if err != nil {
		panic(err)
	}
	return owner
}

func testPayerPubkeyHash() *big.Int {
	return protocol.Sha256BEField(testSolanaPubkey())
}

func testSolanaPkField(t testing.TB) *big.Int {
	return testSolanaPkFieldSeed(t, 0x42)
}

func testSolanaPkFieldSeed(t testing.TB, seed byte) *big.Int {
	pubkey := testSolanaPubkeySeed(seed)
	var bytes [32]byte
	copy(bytes[:], pubkey)
	hash, err := protocol.SolanaPkField(bytes)
	if err != nil {
		if t != nil {
			t.Fatalf("solana pk hash: %v", err)
		}
		panic(err)
	}
	return hash
}

func testSolanaPubkey() []byte {
	return testSolanaPubkeySeed(0x42)
}

func testSolanaPubkeySeed(seedByte byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	key := ed25519.NewKeyFromSeed(seed)
	return key[32:]
}

func fieldsFromUtxo(u protocol.Utxo) UtxoCircuitFields {
	return UtxoCircuitFields{
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

func circuitFieldsToUtxo(fields UtxoCircuitFields) protocol.Utxo {
	return protocol.Utxo{
		Domain:        spptest.AsBigInt(fields.Domain),
		Owner:         spptest.AsBigInt(fields.Owner),
		Asset:         spptest.AsBigInt(fields.Asset),
		Amount:        spptest.AsBigInt(fields.Amount),
		Blinding:      spptest.AsBigInt(fields.Blinding),
		DataHash:      spptest.AsBigInt(fields.DataHash),
		ZoneDataHash:  spptest.AsBigInt(fields.ZoneDataHash),
		ZoneProgramID: spptest.AsBigInt(fields.ZoneProgramID),
	}
}
