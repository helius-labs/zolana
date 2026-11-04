package shared_test

import (
	"math/big"
	"testing"

	customring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom"
	. "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

var exitShape = protocol.Shape{NInputs: 2, NOutputs: 2}

func asCustomRingAuthorityExit(a *testAssignment) *customring.CustomRingAuthorityExitCircuit {
	return &customring.CustomRingAuthorityExitCircuit{
		CachedInputs: a.CachedInputs,
		Public: customring.CustomRingAuthorityExitPublic{
			Nullifiers:                   a.InputNullifiers(),
			OutputHashes:                 a.OutputHashes(),
			TreeSlots:                    a.TreeSlots,
			OutputTreeID:                 a.OutputTreeID,
			PrivateTxHash:                a.PrivateTxHash,
			ExternalDataHash:             a.ExternalDataHash,
			PublicAssets:                 a.PublicAssets,
			PublicAmounts:                a.PublicAmounts,
			RingProgramID:                a.RingProgramID,
			SignerPkHashes:               a.TransactionSignerPkHashes(),
			InputFlags:                   a.InputFlags,
			PublishedOutputOwnerPkHashes: a.PublishedOutputOwnerPkHashes(),
			PublicInputHash:              a.PublicInputHash,
		},
		Private: customring.CustomRingAuthorityExitPrivate{
			Inputs:              a.coreInputs(),
			InputOwnerPkHashes:  a.InputOwnerPkHashes(),
			Outputs:             a.outputUtxos(),
			OutputOwnerPkHashes: a.OutputOwnerPkHashes(),
			OutputNullifierPks:  a.outputNullifierPks(),
			BlindingSeed:        a.BlindingSeed,
		},
	}
}

func newExitCircuit(t testing.TB, shape protocol.Shape) frontend.Circuit {
	t.Helper()
	circuit, err := customring.NewCustomRingAuthorityExitCircuit(Shape(shape))
	if err != nil {
		t.Fatal(err)
	}
	return circuit
}

// Slot 0 exits to outsideRecipient, every later output stays in the ring.
func buildExitAssignment(t testing.TB, shape protocol.Shape) *testAssignment {
	t.Helper()
	ring := ringAuthorityRing()
	inputs, outputs := defaultBalancedUtxos(t, shape)
	for i := range inputs {
		inputs[i].RingProgramID = new(big.Int).Set(ring)
	}
	for i := 1; i < len(outputs); i++ {
		outputs[i].RingProgramID = new(big.Int).Set(ring)
	}
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)
	assignment.RingProgramID = new(big.Int).Set(ring)
	assignment.SignerPkHashes = []frontend.Variable{testPayerPkHash()}
	retagExitOutput(t, assignment, 0, outsideRecipient(t))
	refreshExitHashes(t, assignment)
	return assignment
}

func retagExitOutput(t testing.TB, assignment *testAssignment, slot int, pkField *big.Int) {
	t.Helper()
	owner, err := protocol.OwnerHash(pkField, spptest.AsBigInt(assignment.Outputs[slot].NullifierPk))
	if err != nil {
		t.Fatalf("owner hash: %v", err)
	}
	assignment.Outputs[slot].Utxo.Owner = owner
	assignment.Outputs[slot].OwnerPkHash = pkField
}

// Slot 1 becomes a dummy publishing tag, and slot 0 takes the whole amount.
func padExitOutput(t testing.TB, assignment *testAssignment, tag frontend.Variable) {
	t.Helper()
	total := int64(0)
	for i := range assignment.Inputs {
		total += spptest.AsBigInt(assignment.Inputs[i].Utxo.Amount).Int64()
	}
	assignment.Outputs[0].Utxo.Amount = spptest.Fe(total)
	assignment.Outputs[1].Utxo = fieldsFromUtxo(emptyOutputUtxo())
	assignment.Outputs[1].OwnerPkHash = tag
	assignment.Outputs[1].NullifierPk = spptest.Fe(55)
}

func refreshExitHashes(t testing.TB, assignment *testAssignment) {
	t.Helper()
	refreshDerivedOutputBlindings(t, assignment)
	refreshExitPrivateTxHash(t, assignment)
	refreshExitPublicInputHash(t, assignment, assignment.PublishedOutputOwnerPkHashes())
}

func refreshExitPrivateTxHash(t testing.TB, assignment *testAssignment) {
	t.Helper()
	inputHashes := make([]*big.Int, len(assignment.Inputs))
	addressNullifiers := make([]*big.Int, len(assignment.Inputs))
	for i := range assignment.Inputs {
		inputHashes[i] = testUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[i].Utxo), assignment.inputTreeID(i))
		addressNullifiers[i] = big.NewInt(0)
		if spptest.AsBigInt(assignment.Inputs[i].Utxo.Domain).Int64() == AddressDomain {
			inputHashes[i] = big.NewInt(0)
			addressNullifiers[i] = spptest.AsBigInt(assignment.Inputs[i].Nullifier)
		}
	}
	outputHashes := make([]*big.Int, len(assignment.Outputs))
	for i := range assignment.Outputs {
		outputHashes[i] = big.NewInt(0)
		if spptest.AsBigInt(assignment.Outputs[i].Utxo.Domain).Int64() != DummyDomain {
			outputHashes[i] = spptest.AsBigInt(assignment.Outputs[i].Hash)
		}
	}
	assignment.PrivateTxHash = spptest.MustPrivateTxHash(
		t,
		inputHashes,
		outputHashes,
		addressNullifiers,
		assignment.privateTxBlinding(t),
	)
}

func refreshExitPublicInputHash(t testing.TB, assignment *testAssignment, published []frontend.Variable) {
	t.Helper()
	publicInputs := protocol.PublicInputs{
		Nullifiers:          spptest.ToBigInts(assignment.InputNullifiers()),
		OutputUtxoHashes:    spptest.ToBigInts(assignment.OutputHashes()),
		PrivateTxHash:       spptest.AsBigInt(assignment.PrivateTxHash),
		ExternalDataHash:    spptest.AsBigInt(assignment.ExternalDataHash),
		RingProgramID:       spptest.AsBigInt(assignment.RingProgramID),
		InputFlags:          spptest.AsBigInt(assignment.InputFlags),
		SignerPkHashes:      spptest.ToBigInts(assignment.TransactionSignerPkHashes()),
		BindOutputOwnerTags: true,
		OutputOwnerPkHashes: spptest.ToBigInts(published),
	}
	for i := 0; i < NPublicSlots; i++ {
		publicInputs.PublicAssets[i] = spptest.AsBigInt(assignment.PublicAssets[i])
		publicInputs.PublicAmounts[i] = spptest.AsBigInt(assignment.PublicAmounts[i])
	}
	assignment.PublicInputHash = testPublicInputHash(t, publicInputs, assignment.TreeSlots, assignment.OutputTreeID, assignment.CachedInputs)
}

func assertExitSolves(t *testing.T, shape protocol.Shape, assignment *testAssignment) {
	t.Helper()
	test.NewAssert(t).SolvingSucceeded(newExitCircuit(t, shape), asCustomRingAuthorityExit(assignment), test.WithCurves(ecc.BN254))
}

// A nil published keeps the masked vector the assignment derives.
func assertExitFails(t *testing.T, shape protocol.Shape, assignment *testAssignment, published []frontend.Variable) {
	t.Helper()
	witness := asCustomRingAuthorityExit(assignment)
	if published != nil {
		witness.Public.PublishedOutputOwnerPkHashes = published
	}
	test.NewAssert(t).SolvingFailed(newExitCircuit(t, shape), witness, test.WithCurves(ecc.BN254))
}

func TestRingAuthorityExitSolvesForAuthorityShapes(t *testing.T) {
	for _, shape := range []protocol.Shape{{NInputs: 2, NOutputs: 2}, {NInputs: 4, NOutputs: 4}} {
		t.Run(shape.String(), func(t *testing.T) {
			assertExitSolves(t, shape, buildExitAssignment(t, shape))
		})
	}
}

func TestRingAuthorityExitSolvesWithNoExit(t *testing.T) {
	assignment := buildExitAssignment(t, exitShape)
	assignment.Outputs[0].Utxo.RingProgramID = assignment.RingProgramID
	refreshExitHashes(t, assignment)
	assertExitSolves(t, exitShape, assignment)
}

func TestRingAuthorityExitPublicInputHashBindsEveryField(t *testing.T) {
	assignment := buildExitAssignment(t, exitShape)
	assignment.Outputs[1].Utxo.RingProgramID = big.NewInt(0)
	refreshExitHashes(t, assignment)
	assertPublicInputHashBindsEveryField(
		t,
		newExitCircuit(t, exitShape),
		assignment,
		func() frontend.Circuit { return asCustomRingAuthorityExit(assignment) },
		func() { refreshExitPublicInputHash(t, assignment, assignment.PublishedOutputOwnerPkHashes()) },
		publicInputHashBindingOptions{
			includeRingProgramID:       true,
			includeOutputOwnerPkHashes: true,
			signerWidth:                1,
		},
	)
}

func TestRingAuthorityExitRejectsInputOutsideTheRing(t *testing.T) {
	for name, ring := range map[string]*big.Int{"default": big.NewInt(0), "foreign": spptest.Fe(0x5b)} {
		t.Run(name, func(t *testing.T) {
			assignment := buildExitAssignment(t, exitShape)
			assignment.Inputs[0].Utxo.RingProgramID = ring
			rebuildAfterOwnerChange(t, assignment)
			refreshExitHashes(t, assignment)
			assertExitFails(t, exitShape, assignment, nil)
		})
	}
}

func TestRingAuthorityExitRejectsForeignRingOutput(t *testing.T) {
	assignment := buildExitAssignment(t, exitShape)
	assignment.Outputs[1].Utxo.RingProgramID = spptest.Fe(0x5b)
	refreshExitHashes(t, assignment)
	assertExitFails(t, exitShape, assignment, nil)
}

func TestRingAuthorityExitRejectsRingDataOnExitOutput(t *testing.T) {
	assignment := buildExitAssignment(t, exitShape)
	assignment.Outputs[0].Utxo.RingDataHash = spptest.Fe(0x77)
	refreshExitHashes(t, assignment)
	assertExitFails(t, exitShape, assignment, nil)
}

func TestRingAuthorityExitRejectsZeroRingProgramID(t *testing.T) {
	assignment := buildExitAssignment(t, exitShape)
	assignment.RingProgramID = big.NewInt(0)
	for i := range assignment.Inputs {
		assignment.Inputs[i].Utxo.RingProgramID = big.NewInt(0)
	}
	assignment.Outputs[1].Utxo.RingProgramID = big.NewInt(0)
	rebuildAfterOwnerChange(t, assignment)
	refreshExitHashes(t, assignment)
	assertExitFails(t, exitShape, assignment, nil)
}

func TestRingAuthorityExitRejectsWrongNullifierSecret(t *testing.T) {
	assignment := buildExitAssignment(t, exitShape)
	assignment.Inputs[0].NullifierSecret = spptest.Fe(12345)
	assertExitFails(t, exitShape, assignment, nil)
}

func TestRingAuthorityExitRejectsAddressInput(t *testing.T) {
	assignment := buildExitAssignment(t, exitShape)
	ownerPkHash := addressOwnerPkHash(t)
	assignment.Outputs[0].Utxo.Amount = assignment.Inputs[0].Utxo.Amount
	assignment.Outputs[1].Utxo.Amount = spptest.Fe(0)
	setAddressSlot(t, &assignment.Inputs[1], ownerPkHash, ownerPkHash, spptest.Fe(0xABCDEF))
	refreshExitHashes(t, assignment)
	assertExitFails(t, exitShape, assignment, nil)
}

func TestRingAuthorityExitRejectsTagThatDoesNotOpenTheOwner(t *testing.T) {
	assignment := buildExitAssignment(t, exitShape)
	assignment.Outputs[0].OwnerPkHash = testSolanaPkFieldSeed(t, 0x44)
	refreshExitHashes(t, assignment)
	assertExitFails(t, exitShape, assignment, nil)
}

// The zero tag opens the owner and matches the mask, so only the named exit owner rule refuses it.
func TestRingAuthorityExitRejectsZeroExitTag(t *testing.T) {
	assignment := buildExitAssignment(t, exitShape)
	retagExitOutput(t, assignment, 0, big.NewInt(0))
	refreshExitHashes(t, assignment)
	assertExitFails(t, exitShape, assignment, nil)
}

func TestRingAuthorityExitRejectsExitPublishingAnotherTag(t *testing.T) {
	for name, tag := range map[string]frontend.Variable{"zero": 0, "other": testSolanaPkFieldSeed(t, 0x44)} {
		t.Run(name, func(t *testing.T) {
			assignment := buildExitAssignment(t, exitShape)
			published := []frontend.Variable{tag, 0}
			refreshExitPublicInputHash(t, assignment, published)
			assertExitFails(t, exitShape, assignment, published)
		})
	}
}

func TestRingAuthorityExitRejectsRingOutputPublishingItsOwner(t *testing.T) {
	assignment := buildExitAssignment(t, exitShape)
	published := []frontend.Variable{assignment.Outputs[0].OwnerPkHash, assignment.Outputs[1].OwnerPkHash}
	refreshExitPublicInputHash(t, assignment, published)
	assertExitFails(t, exitShape, assignment, published)
}

func TestRingAuthorityExitDummyOutputTags(t *testing.T) {
	recipient := outsideRecipient(t)
	for name, tag := range map[string]frontend.Variable{
		"zero":            0,
		"exit owner":      recipient,
		"authority payer": testPayerPkHash(),
	} {
		t.Run(name, func(t *testing.T) {
			assignment := buildExitAssignment(t, exitShape)
			padExitOutput(t, assignment, tag)
			refreshExitHashes(t, assignment)
			published := []frontend.Variable{recipient, tag}
			refreshExitPublicInputHash(t, assignment, published)
			witness := asCustomRingAuthorityExit(assignment)
			witness.Public.PublishedOutputOwnerPkHashes = published
			test.NewAssert(t).SolvingSucceeded(newExitCircuit(t, exitShape), witness, test.WithCurves(ecc.BN254))
		})
	}
}

// A hidden ring recipient copied into a dummy tag would publish a private identity.
func TestRingAuthorityExitRejectsDummyOutputNamingARingRecipient(t *testing.T) {
	assignment := buildExitAssignment(t, exitShape)
	assignment.Outputs[0].Utxo.RingProgramID = assignment.RingProgramID
	padExitOutput(t, assignment, assignment.Outputs[0].OwnerPkHash)
	refreshExitHashes(t, assignment)
	published := []frontend.Variable{0, assignment.Outputs[0].OwnerPkHash}
	refreshExitPublicInputHash(t, assignment, published)
	assertExitFails(t, exitShape, assignment, published)
}

func TestRingAuthorityExitCompactOutputPublishesZero(t *testing.T) {
	assignment := buildExitAssignment(t, exitShape)
	padExitOutput(t, assignment, 0)
	refreshDerivedOutputBlindings(t, assignment)
	refreshExitPrivateTxHash(t, assignment)
	assignment.Outputs[1].Hash = spptest.Fe(0)
	published := []frontend.Variable{outsideRecipient(t), 0}
	refreshExitPublicInputHash(t, assignment, published)
	assertExitSolves(t, exitShape, assignment)

	tagged := []frontend.Variable{outsideRecipient(t), outsideRecipient(t)}
	assignment.Outputs[1].OwnerPkHash = outsideRecipient(t)
	refreshExitPublicInputHash(t, assignment, tagged)
	assertExitFails(t, exitShape, assignment, tagged)
}

func TestRingAuthorityExitDataOutputMustBelongToASpentOwner(t *testing.T) {
	spentOwner := buildExitAssignment(t, exitShape)
	spentOwner.Outputs[1].Utxo.DataHash = spptest.Fe(0x99)
	refreshExitHashes(t, spentOwner)
	assertExitSolves(t, exitShape, spentOwner)

	stranger := buildExitAssignment(t, exitShape)
	stranger.Outputs[0].Utxo.DataHash = spptest.Fe(0x99)
	refreshExitHashes(t, stranger)
	assertExitFails(t, exitShape, stranger, nil)
}

// With no cached selector the program publishes the empty selection, which opens no cached input.
func TestRingAuthorityExitRejectsCachedInputUnderEmptySelection(t *testing.T) {
	assignment := buildExitAssignment(t, exitShape)
	assignment.CachedInputs.IsCached[0] = 1
	assertExitFails(t, exitShape, assignment, nil)
}

func TestRingAuthorityExitBindsTheCacheSelection(t *testing.T) {
	for name, change := range map[string]func(*CachedInputs){
		"tree id":         func(cache *CachedInputs) { cache.TreeID = 1 },
		"read hash chain": func(cache *CachedInputs) { cache.ReadHashChain = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			assignment := buildExitAssignment(t, exitShape)
			change(&assignment.CachedInputs)
			assertExitFails(t, exitShape, assignment, nil)
		})
	}
}
