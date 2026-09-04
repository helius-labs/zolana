package shared_test

import (
	"crypto/ed25519"
	"math/big"
	"testing"

	customring "zolana/prover/circuits/spp_transaction/custom"
	defaultring "zolana/prover/circuits/spp_transaction/default"
	. "zolana/prover/circuits/spp_transaction/shared"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark/frontend"
)

func TestShapeValidate(t *testing.T) {
	if err := (Shape{NInputs: 0, NOutputs: 1}).Validate(); err == nil {
		t.Fatal("expected error for zero inputs")
	}
	if err := (Shape{NInputs: 1, NOutputs: 0}).Validate(); err == nil {
		t.Fatal("expected error for zero outputs")
	}
	if err := (Shape{NInputs: 1, NOutputs: 1}).Validate(); err != nil {
		t.Fatalf("valid shape rejected: %v", err)
	}
}

// testInput is the variant-agnostic per-slot test witness: the slimmed shared
// Input plus the hoisted signals that live in the variant Public structs.
type testInput struct {
	Input
	Nullifier         frontend.Variable
	UtxoTreeRoot      frontend.Variable
	NullifierTreeRoot frontend.Variable
	OwnerPkHash       frontend.Variable
}

type testOutput struct {
	Utxo        UtxoCircuitFields
	Hash        frontend.Variable
	OwnerPkHash frontend.Variable
	NullifierPk frontend.Variable
}

// testAssignment carries every value any variant needs; the as<Variant>
// materializers project it onto the variant Public/Private structs.
type testAssignment struct {
	Shape              Shape
	Inputs             []testInput
	Outputs            []testOutput
	OutputBlindingSeed frontend.Variable

	ExternalDataHash  frontend.Variable
	PrivateTxHash     frontend.Variable
	PrivateTxBlinding frontend.Variable
	PublicAssets      [NPublicSlots]frontend.Variable
	PublicAmounts     [NPublicSlots]frontend.Variable
	RingProgramID     frontend.Variable
	AllowDummyInputs  frontend.Variable
	SignerPkHashes    []frontend.Variable

	PublicInputHash frontend.Variable
}

func (a *testAssignment) InputNullifiers() []frontend.Variable {
	out := make([]frontend.Variable, len(a.Inputs))
	for i := range a.Inputs {
		out[i] = a.Inputs[i].Nullifier
	}
	return out
}

func (a *testAssignment) InputUtxoRoots() []frontend.Variable {
	out := make([]frontend.Variable, len(a.Inputs))
	for i := range a.Inputs {
		out[i] = a.Inputs[i].UtxoTreeRoot
	}
	return out
}

func (a *testAssignment) InputNullifierTreeRoots() []frontend.Variable {
	out := make([]frontend.Variable, len(a.Inputs))
	for i := range a.Inputs {
		out[i] = a.Inputs[i].NullifierTreeRoot
	}
	return out
}

func (a *testAssignment) InputOwnerPkHashes() []frontend.Variable {
	out := make([]frontend.Variable, len(a.Inputs))
	for i := range a.Inputs {
		out[i] = a.Inputs[i].OwnerPkHash
	}
	return out
}

func (a *testAssignment) TransactionSignerPkHashes() []frontend.Variable {
	if a.SignerPkHashes != nil {
		return a.SignerPkHashes
	}
	out := make([]frontend.Variable, a.Shape.NInputs+1)
	out[0] = testPayerPkHash()
	for i := range out {
		if i != 0 {
			out[i] = 0
		}
	}
	return out
}

func (a *testAssignment) AuthoritySignerPkHashes() []frontend.Variable {
	return a.TransactionSignerPkHashes()[:1]
}

func (a *testAssignment) OutputHashes() []frontend.Variable {
	out := make([]frontend.Variable, len(a.Outputs))
	for i := range a.Outputs {
		out[i] = a.Outputs[i].Hash
	}
	return out
}

func (a *testAssignment) OutputOwnerPkHashes() []frontend.Variable {
	out := make([]frontend.Variable, len(a.Outputs))
	for i := range a.Outputs {
		out[i] = a.Outputs[i].OwnerPkHash
	}
	return out
}

func (a *testAssignment) PublishedOutputOwnerPkHashes() []frontend.Variable {
	out := make([]frontend.Variable, len(a.Outputs))
	for i := range a.Outputs {
		if spptest.AsBigInt(a.Outputs[i].Utxo.RingProgramID).Sign() == 0 {
			out[i] = a.Outputs[i].OwnerPkHash
		} else {
			out[i] = 0
		}
	}
	return out
}

func (a *testAssignment) coreInputs() []Input {
	out := make([]Input, len(a.Inputs))
	for i := range a.Inputs {
		out[i] = a.Inputs[i].Input
	}
	return out
}

func (a *testAssignment) outputUtxos() []UtxoCircuitFields {
	out := make([]UtxoCircuitFields, len(a.Outputs))
	for i := range a.Outputs {
		out[i] = a.Outputs[i].Utxo
	}
	return out
}

func (a *testAssignment) outputNullifierPks() []frontend.Variable {
	out := make([]frontend.Variable, len(a.Outputs))
	for i := range a.Outputs {
		out[i] = a.Outputs[i].NullifierPk
	}
	return out
}

func asCustomRingEddsaOnly(a *testAssignment) frontend.Circuit {
	return &customring.CustomRingEddsaOnlyCircuit{
		Public: customring.CustomRingEddsaOnlyPublic{
			Nullifiers:                   a.InputNullifiers(),
			OutputHashes:                 a.OutputHashes(),
			UtxoTreeRoots:                a.InputUtxoRoots(),
			NullifierTreeRoots:           a.InputNullifierTreeRoots(),
			PrivateTxHash:                a.PrivateTxHash,
			ExternalDataHash:             a.ExternalDataHash,
			PublicAssets:                 a.PublicAssets,
			PublicAmounts:                a.PublicAmounts,
			RingProgramID:                a.RingProgramID,
			AllowDummyInputs:             a.AllowDummyInputs,
			SignerPkHashes:               a.TransactionSignerPkHashes(),
			PublishedOutputOwnerPkHashes: a.PublishedOutputOwnerPkHashes(),
			PublicInputHash:              a.PublicInputHash,
		},
		Private: customring.CustomRingEddsaOnlyPrivate{
			Inputs:              a.coreInputs(),
			InputOwnerPkHashes:  a.InputOwnerPkHashes(),
			Outputs:             a.outputUtxos(),
			OutputOwnerPkHashes: a.OutputOwnerPkHashes(),
			OutputNullifierPks:  a.outputNullifierPks(),
			OutputBlindingSeed:  a.OutputBlindingSeed,
			PrivateTxBlinding:   a.PrivateTxBlinding,
		},
	}
}

func asCustomRingAuthority(a *testAssignment) frontend.Circuit {
	return &customring.CustomRingAuthorityCircuit{
		Public: customring.CustomRingAuthorityPublic{
			Nullifiers:         a.InputNullifiers(),
			OutputHashes:       a.OutputHashes(),
			UtxoTreeRoots:      a.InputUtxoRoots(),
			NullifierTreeRoots: a.InputNullifierTreeRoots(),
			PrivateTxHash:      a.PrivateTxHash,
			ExternalDataHash:   a.ExternalDataHash,
			PublicAssets:       a.PublicAssets,
			PublicAmounts:      a.PublicAmounts,
			RingProgramID:      a.RingProgramID,
			SignerPkHashes:     a.AuthoritySignerPkHashes(),
			AllowDummyInputs:   a.AllowDummyInputs,
			PublicInputHash:    a.PublicInputHash,
		},
		Private: customring.CustomRingAuthorityPrivate{
			Inputs:             a.coreInputs(),
			InputOwnerPkHashes: a.InputOwnerPkHashes(),
			Outputs:            a.outputUtxos(),
			OutputBlindingSeed: a.OutputBlindingSeed,
			PrivateTxBlinding:  a.PrivateTxBlinding,
		},
	}
}

func asDefaultRingEddsaOnly(a *testAssignment) frontend.Circuit {
	return &defaultring.DefaultRingEddsaOnlyCircuit{
		Public: defaultring.DefaultRingEddsaOnlyPublic{
			Nullifiers:          a.InputNullifiers(),
			OutputHashes:        a.OutputHashes(),
			UtxoTreeRoots:       a.InputUtxoRoots(),
			NullifierTreeRoots:  a.InputNullifierTreeRoots(),
			PrivateTxHash:       a.PrivateTxHash,
			ExternalDataHash:    a.ExternalDataHash,
			PublicAssets:        a.PublicAssets,
			PublicAmounts:       a.PublicAmounts,
			AllowDummyInputs:    a.AllowDummyInputs,
			SignerPkHashes:      a.TransactionSignerPkHashes(),
			OutputOwnerPkHashes: a.OutputOwnerPkHashes(),
			PublicInputHash:     a.PublicInputHash,
		},
		Private: defaultring.DefaultRingEddsaOnlyPrivate{
			Inputs:             a.coreInputs(),
			InputOwnerPkHashes: a.InputOwnerPkHashes(),
			Outputs:            a.outputUtxos(),
			OutputNullifierPks: a.outputNullifierPks(),
			OutputBlindingSeed: a.OutputBlindingSeed,
			PrivateTxBlinding:  a.PrivateTxBlinding,
		},
	}
}

func noPublicSlots() ([NPublicSlots]*big.Int, [NPublicSlots]*big.Int) {
	assets := [NPublicSlots]*big.Int{}
	amounts := [NPublicSlots]*big.Int{}
	for i := 0; i < NPublicSlots; i++ {
		assets[i] = big.NewInt(0)
		amounts[i] = big.NewInt(0)
	}
	return assets, amounts
}

func solPublicSlot(amount int64) ([NPublicSlots]*big.Int, [NPublicSlots]*big.Int) {
	assets, amounts := noPublicSlots()
	if amount != 0 {
		assets[0] = protocol.SolAsset()
	}
	amounts[0] = big.NewInt(amount)
	return assets, amounts
}

func splPublicSlot(asset *big.Int, amount int64) ([NPublicSlots]*big.Int, [NPublicSlots]*big.Int) {
	assets, amounts := noPublicSlots()
	assets[1] = new(big.Int).Set(asset)
	amounts[1] = big.NewInt(amount)
	return assets, amounts
}

func buildCircuitAssignment(t testing.TB, shape protocol.Shape) *testAssignment {
	t.Helper()

	inputUtxos, outputUtxos := defaultBalancedUtxos(t, shape)
	return buildCircuitAssignmentFromUtxos(t, shape, inputUtxos, outputUtxos)
}

func buildCircuitAssignmentFromUtxos(
	t testing.TB,
	shape protocol.Shape,
	inputUtxos []protocol.Utxo,
	outputUtxos []protocol.Utxo,
) *testAssignment {
	t.Helper()
	assets, amounts := noPublicSlots()
	return buildCircuitAssignmentExact(t, shape, inputUtxos, outputUtxos, assets, amounts)
}

func buildCircuitAssignmentExact(
	t testing.TB,
	shape protocol.Shape,
	inputUtxos []protocol.Utxo,
	outputUtxos []protocol.Utxo,
	publicAssets [NPublicSlots]*big.Int,
	publicAmounts [NPublicSlots]*big.Int,
) *testAssignment {
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
		if utxo.Domain.Cmp(big.NewInt(protocol.DummyDomain)) == 0 {
			inputOwnerPkHashes[i] = big.NewInt(0)
		} else {
			inputOwnerPkHashes[i] = testSolanaPkField(t)
		}
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
	outputBlindingSeed := spptest.Fe(4242)
	firstNullifier := spptest.AsBigInt(nullifiers[0])
	for i := range outputUtxos {
		blinding, err := protocol.OutputBlinding(firstNullifier, outputBlindingSeed, i)
		outputUtxos[i].Blinding = spptest.MustHash(t, blinding, err)
	}

	outputCircuitUtxos := make([]UtxoCircuitFields, shape.NOutputs)
	OutputHashes := make([]*big.Int, shape.NOutputs)
	outputHashVariables := make([]frontend.Variable, shape.NOutputs)
	outputOwnerPkHashes := make([]*big.Int, shape.NOutputs)
	outputNullifierPks := make([]*big.Int, shape.NOutputs)
	for i := 0; i < shape.NOutputs; i++ {
		utxo := outputUtxos[i]
		outputCircuitUtxos[i] = fieldsFromUtxo(utxo)
		outputHash := spptest.MustUtxoHash(t, utxo)
		OutputHashes[i] = outputHash
		outputHashVariables[i] = outputHash
		outputOwnerPkHashes[i] = testSolanaPkField(t)
		outputNullifierPks[i] = spptest.MustNullifierPk(t, spptest.Fe(99))
	}

	externalDataHash := spptest.Fe(300)
	privateTxBlinding := spptest.Fe(0xB11D)
	privateTxHash := spptest.MustPrivateTxHash(
		t,
		inputHashes,
		OutputHashes,
		noAddressHashes(shape.NInputs),
		externalDataHash,
		privateTxBlinding,
	)
	payerPkHash := testPayerPkHash()
	signerPkHashes := zeroFields(shape.NInputs + 1)
	signerPkHashes[0] = new(big.Int).Set(payerPkHash)
	nextSigner := 1
	seenSigners := []*big.Int{payerPkHash}
	for _, owner := range inputOwnerPkHashes {
		if owner.Sign() == 0 {
			continue
		}
		seen := false
		for _, existing := range seenSigners {
			if existing.Cmp(owner) == 0 {
				seen = true
				break
			}
		}
		if seen {
			continue
		}
		seenSigners = append(seenSigners, owner)
		signerPkHashes[nextSigner] = new(big.Int).Set(owner)
		nextSigner++
	}

	signedAmounts := [NPublicSlots]*big.Int{}
	for i := 0; i < NPublicSlots; i++ {
		signedAmounts[i] = protocol.SignedToField(publicAmounts[i])
	}
	publicInputs := protocol.PublicInputs{
		Nullifiers:         spptest.ToBigInts(nullifiers),
		OutputUtxoHashes:   OutputHashes,
		UtxoTreeRoots:      utxoTreeRoots,
		NullifierTreeRoots: nullifierTreeRoots,
		PrivateTxHash:      privateTxHash,
		ExternalDataHash:   externalDataHash,
		PublicAssets:       publicAssets,
		PublicAmounts:      signedAmounts,
		// Nonzero test ring id: the custom-ring circuits assert RingProgramID
		// != 0; the default-ring refresh overrides it back to 0.
		RingProgramID:       spptest.Fe(0x5A),
		AllowDummyInputs:    spptest.Fe(1),
		SignerPkHashes:      signerPkHashes,
		BindOutputOwnerTags: true,
	}
	publishedOutputOwnerPkHashes := make([]*big.Int, len(outputOwnerPkHashes))
	for i := range outputOwnerPkHashes {
		if outputUtxos[i].RingProgramID.Sign() == 0 {
			publishedOutputOwnerPkHashes[i] = outputOwnerPkHashes[i]
		} else {
			publishedOutputOwnerPkHashes[i] = big.NewInt(0)
		}
	}
	publicInputs.OutputOwnerPkHashes = publishedOutputOwnerPkHashes
	publicInputHashValue, err := protocol.PublicInputHash(publicInputs)
	publicInputHash := spptest.MustHash(t, publicInputHashValue, err)

	inputs := make([]testInput, shape.NInputs)
	for i := 0; i < shape.NInputs; i++ {
		inputs[i] = testInput{
			Input: Input{
				Utxo:                     inputCircuitUtxos[i],
				StatePathElements:        statePathElementsVars[i],
				StatePathIndex:           statePathIndexVars[i],
				NullifierLowValue:        nfLowValueVars[i],
				NullifierNextValue:       nfNextValueVars[i],
				NullifierLowPathElements: nfLowPathElementVars[i],
				NullifierLowPathIndex:    nfLowPathIndexVars[i],
				NullifierSecret:          nullifierSecrets[i],
			},
			UtxoTreeRoot:      utxoTreeRoots[i],
			NullifierTreeRoot: nullifierTreeRoots[i],
			Nullifier:         nullifiers[i],
			OwnerPkHash:       inputOwnerPkHashes[i],
		}
	}
	outputs := make([]testOutput, shape.NOutputs)
	for i := 0; i < shape.NOutputs; i++ {
		outputs[i] = testOutput{
			Utxo:        outputCircuitUtxos[i],
			Hash:        outputHashVariables[i],
			OwnerPkHash: outputOwnerPkHashes[i],
			NullifierPk: outputNullifierPks[i],
		}
	}

	circuit := &testAssignment{
		Shape:              Shape(shape),
		Inputs:             inputs,
		Outputs:            outputs,
		OutputBlindingSeed: outputBlindingSeed,
		PrivateTxBlinding:  privateTxBlinding,
		ExternalDataHash:   externalDataHash,
		PrivateTxHash:      privateTxHash,
		RingProgramID:      publicInputs.RingProgramID,
		AllowDummyInputs:   publicInputs.AllowDummyInputs,
		SignerPkHashes:     asFrontendVariables(publicInputs.SignerPkHashes),
		PublicInputHash:    publicInputHash,
	}
	for i := 0; i < NPublicSlots; i++ {
		circuit.PublicAssets[i] = publicInputs.PublicAssets[i]
		circuit.PublicAmounts[i] = publicInputs.PublicAmounts[i]
	}
	return circuit
}

func zeroFields(length int) []*big.Int {
	out := make([]*big.Int, length)
	for i := range out {
		out[i] = big.NewInt(0)
	}
	return out
}

func asFrontendVariables(values []*big.Int) []frontend.Variable {
	out := make([]frontend.Variable, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
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

func refreshPublicInputHash(t testing.TB, assignment *testAssignment) {
	refreshPublicInputHashVariant(t, assignment, true, false)
}

func refreshPublicInputHashVariant(t testing.TB, assignment *testAssignment, bindOutputOwnerTags, ringAuthority bool) {
	t.Helper()
	// Every owner-signed rail now appends an output-owner chain. Custom-ring
	// assignments use the masked vector; authority is the sole omitted mode.
	bindOutputOwnerTags = !ringAuthority
	publicInputs := protocol.PublicInputs{
		Nullifiers:          spptest.ToBigInts(assignment.InputNullifiers()),
		OutputUtxoHashes:    spptest.ToBigInts(assignment.OutputHashes()),
		UtxoTreeRoots:       spptest.ToBigInts(assignment.InputUtxoRoots()),
		NullifierTreeRoots:  spptest.ToBigInts(assignment.InputNullifierTreeRoots()),
		PrivateTxHash:       spptest.AsBigInt(assignment.PrivateTxHash),
		ExternalDataHash:    spptest.AsBigInt(assignment.ExternalDataHash),
		RingProgramID:       spptest.AsBigInt(assignment.RingProgramID),
		AllowDummyInputs:    spptest.AsBigInt(assignment.AllowDummyInputs),
		SignerPkHashes:      spptest.ToBigInts(assignment.TransactionSignerPkHashes()),
		BindOutputOwnerTags: bindOutputOwnerTags,
	}
	if ringAuthority {
		publicInputs.SignerPkHashes = publicInputs.SignerPkHashes[:1]
	}
	for i := 0; i < NPublicSlots; i++ {
		publicInputs.PublicAssets[i] = spptest.AsBigInt(assignment.PublicAssets[i])
		publicInputs.PublicAmounts[i] = spptest.AsBigInt(assignment.PublicAmounts[i])
	}
	if bindOutputOwnerTags {
		publicInputs.OutputOwnerPkHashes = spptest.ToBigInts(assignment.PublishedOutputOwnerPkHashes())
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
		RingDataHash:  spptest.Fe(0),
		RingProgramID: spptest.Fe(0),
	}
}

func rewriteInputAsSolanaOwner(
	t testing.TB,
	assignment *testAssignment,
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
	for i := range assignment.SignerPkHashes {
		if spptest.AsBigInt(assignment.SignerPkHashes[i]).Sign() == 0 {
			assignment.SignerPkHashes[i] = pkField
			break
		}
	}
	assignment.Inputs[inputIndex].NullifierSecret = nullifierSecret
	rebuildAfterOwnerChange(t, assignment)
}

func rebuildAfterOwnerChange(t testing.TB, assignment *testAssignment) {
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
	refreshDerivedOutputBlindings(t, assignment)

	OutputHashes := spptest.ToBigInts(assignment.OutputHashes())
	privateTxHash := spptest.MustPrivateTxHash(
		t,
		inputHashes,
		OutputHashes,
		noAddressHashes(len(inputHashes)),
		spptest.AsBigInt(assignment.ExternalDataHash),
		spptest.AsBigInt(assignment.PrivateTxBlinding),
	)
	assignment.PrivateTxHash = privateTxHash
	refreshPublicInputHash(t, assignment)
}

func refreshDerivedOutputBlindings(t testing.TB, assignment *testAssignment) {
	t.Helper()
	firstNullifier := spptest.AsBigInt(assignment.Inputs[0].Nullifier)
	seed := spptest.AsBigInt(assignment.OutputBlindingSeed)
	for i := range assignment.Outputs {
		blinding, err := protocol.OutputBlinding(firstNullifier, seed, i)
		assignment.Outputs[i].Utxo.Blinding = spptest.MustHash(t, blinding, err)
		assignment.Outputs[i].Hash = spptest.MustUtxoHash(
			t,
			circuitFieldsToUtxo(assignment.Outputs[i].Utxo),
		)
	}
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

func testPayerPkHash() *big.Int {
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
		RingDataHash:  u.RingDataHash,
		RingProgramID: u.RingProgramID,
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
		RingDataHash:  spptest.AsBigInt(fields.RingDataHash),
		RingProgramID: spptest.AsBigInt(fields.RingProgramID),
	}
}
