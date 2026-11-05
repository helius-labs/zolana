package shared_test

import (
	"encoding/json"
	"math/big"
	"os"
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
	authority := asCustomRingAuthority(a).(*customring.CustomRingAuthorityCircuit)
	authority.Public.SignerPkHashes = a.TransactionSignerPkHashes()
	return &customring.CustomRingAuthorityExitCircuit{
		CachedInputs: a.CachedInputs,
		Public: customring.CustomRingAuthorityExitPublic{
			CustomRingAuthorityPublic:    authority.Public,
			PublishedOutputOwnerPkHashes: a.PublishedOutputOwnerPkHashes(),
		},
		Private: customring.CustomRingAuthorityExitPrivate{
			CustomRingAuthorityPrivate: authority.Private,
			OutputOwnerPkHashes:        a.OutputOwnerPkHashes(),
			OutputNullifierPks:         a.outputNullifierPks(),
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

// Only AssertExitOwnersNamed refuses a zero exit tag.
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

// The empty selection the program publishes without a cached selector opens no cached input.
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

func TestRingAuthorityExitPublicInputHashMatchesTheSharedVector(t *testing.T) {
	raw, err := os.ReadFile("../../../../../test-vectors/public_input_hash.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Transfers []struct {
			Name             string   `json:"name"`
			Nullifiers       []string `json:"nullifiers"`
			OutputHashes     []string `json:"output_hashes"`
			OutputTreeID     int64    `json:"output_tree_id"`
			PrivateTxHash    string   `json:"private_tx_hash"`
			ExternalDataHash string   `json:"external_data_hash"`
			PublicAssets     []string `json:"public_assets"`
			PublicAmounts    []string `json:"public_amounts"`
			RingProgramID    string   `json:"ring_program_id"`
			InputFlags       string   `json:"input_flags"`
			SignerPkHashes   []string `json:"signer_pk_hashes"`
			OutputOwners     []string `json:"output_owner_pk_hashes"`
			CachedInputs     []string `json:"cached_inputs"`
			TreeSlots        []struct {
				ID            int64  `json:"id"`
				UtxoRoot      string `json:"utxo_root"`
				NullifierRoot string `json:"nullifier_root"`
			} `json:"tree_slots"`
			PublicInputHash string `json:"public_input_hash"`
		} `json:"transfers"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	field := func(value string) *big.Int {
		parsed, ok := new(big.Int).SetString(value, 16)
		if !ok {
			t.Fatalf("invalid field %q", value)
		}
		return parsed
	}
	fields := func(values []string) []*big.Int {
		out := make([]*big.Int, len(values))
		for i, value := range values {
			out[i] = field(value)
		}
		return out
	}
	checked := false
	for _, vector := range vectors.Transfers {
		if vector.Name != "ring_authority_exit_2x2" {
			continue
		}
		checked = true
		inputs := protocol.PublicInputs{
			Nullifiers:          fields(vector.Nullifiers),
			OutputUtxoHashes:    fields(vector.OutputHashes),
			OutputTreeID:        big.NewInt(vector.OutputTreeID),
			PrivateTxHash:       field(vector.PrivateTxHash),
			ExternalDataHash:    field(vector.ExternalDataHash),
			RingProgramID:       field(vector.RingProgramID),
			InputFlags:          field(vector.InputFlags),
			SignerPkHashes:      fields(vector.SignerPkHashes),
			BindOutputOwnerTags: true,
			OutputOwnerPkHashes: fields(vector.OutputOwners),
			PreimageTail:        fields(vector.CachedInputs),
		}
		for i := 0; i < NPublicSlots; i++ {
			inputs.PublicAssets[i] = field(vector.PublicAssets[i])
			inputs.PublicAmounts[i] = field(vector.PublicAmounts[i])
		}
		for _, slot := range vector.TreeSlots {
			inputs.TreeSlots = append(inputs.TreeSlots, protocol.TreeSlot{
				ID:            big.NewInt(slot.ID),
				UtxoRoot:      field(slot.UtxoRoot),
				NullifierRoot: field(slot.NullifierRoot),
			})
		}
		hash, err := protocol.PublicInputHash(inputs)
		if err != nil {
			t.Fatal(err)
		}
		if hash.Cmp(field(vector.PublicInputHash)) != 0 {
			t.Fatalf("public input hash %x, want %s", hash, vector.PublicInputHash)
		}
	}
	if !checked {
		t.Fatal("missing vector")
	}
}
