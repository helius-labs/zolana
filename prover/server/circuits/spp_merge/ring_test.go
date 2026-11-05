package merge_test

import (
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	merge "github.com/helius-labs/zolana/prover/server/circuits/spp_merge"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/poseidon"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
)

var (
	fixtureRingProgram = big.NewInt(0xC0FFEE)
	fixtureMergeSeed   = big.NewInt(0x5EED)
)

func ringOptions() mergeFixtureOptions {
	return mergeFixtureOptions{
		rail:           ringFixtureRail,
		ringProgramID:  fixtureRingProgram,
		inputRingData:  []*big.Int{big.NewInt(0xD0), big.NewInt(0xD1)},
		outputRingData: big.NewInt(0xD2),
	}
}

func zeroKeyOptions() mergeFixtureOptions {
	options := ringOptions()
	options.nullifierSecret = big.NewInt(0)
	options.mergeSeed = fixtureMergeSeed
	return options
}

func solveRing(f *mergeWitnessFixture) error {
	return test.IsSolved(merge.NewMergeRingCircuit(len(f.inputs)), f.ringCircuit(), ecc.BN254.ScalarField())
}

func (f *mergeWitnessFixture) rehash(t *testing.T) {
	t.Helper()
	f.publicInputHash = hashChain4(t, f.publicInputPreimage)
}

const (
	ringDataIndex       = 7
	publishedOwnerIndex = 9
)

func TestMergeRingCircuitValidatesPublicSignalLayout(t *testing.T) {
	circuit := merge.NewMergeRingCircuit(defaultFixtureInputs)
	circuit.Nullifiers = circuit.Nullifiers[:len(circuit.Nullifiers)-1]

	_, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		circuit,
		frontend.WithCompressThreshold(300),
	)
	if err == nil {
		t.Fatal("expected malformed ring layout to fail compilation")
	}
	if want := "nullifier count mismatch"; !strings.Contains(err.Error(), want) {
		t.Fatalf("unexpected error: got %q want substring %q", err, want)
	}
}

func TestMergeRingNonzeroKeyPublishesNoOwner(t *testing.T) {
	f := buildMergeFixture(t, ringOptions())
	if f.publishedOwner.Sign() != 0 {
		t.Fatalf("published owner %v", f.publishedOwner)
	}
	if err := solveRing(f); err != nil {
		t.Fatalf("nonzero-key merge: %v", err)
	}
}

func TestMergeRingZeroKeyPublishesItsOwner(t *testing.T) {
	f := buildMergeFixture(t, zeroKeyOptions())
	if f.publishedOwner.Cmp(f.ownerPkHash) != 0 {
		t.Fatalf("published owner %v want %v", f.publishedOwner, f.ownerPkHash)
	}
	if err := solveRing(f); err != nil {
		t.Fatalf("zero-key merge: %v", err)
	}
}

func TestMergeRingRefusesAnyOtherPublishedOwner(t *testing.T) {
	for name, build := range map[string]func() mergeFixtureOptions{
		"zero key":    zeroKeyOptions,
		"nonzero key": ringOptions,
	} {
		t.Run(name, func(t *testing.T) {
			f := buildMergeFixture(t, build())
			other := new(big.Int).Add(f.publishedOwner, big.NewInt(1))
			f.publishedOwner = other
			f.publicInputPreimage[publishedOwnerIndex] = other
			f.rehash(t)
			if err := solveRing(f); err == nil {
				t.Fatal("solved under another published owner")
			}
		})
	}
}

func TestMergeRingRefusesZeroKeyWithoutPublishedOwner(t *testing.T) {
	options := zeroKeyOptions()
	options.publishedOwner = big.NewInt(0)
	if err := solveRing(buildMergeFixture(t, options)); err == nil {
		t.Fatal("zero-key merge solved with no published owner")
	}
}

func TestMergeRingRefusesZeroOwnerUnderZeroKey(t *testing.T) {
	options := zeroKeyOptions()
	options.ownerKeyHash = big.NewInt(0)
	if err := solveRing(buildMergeFixture(t, options)); err == nil {
		t.Fatal("zero-key merge solved for a zero owner")
	}
}

func TestMergeRingRefusesZeroSeedUnderZeroKey(t *testing.T) {
	options := zeroKeyOptions()
	options.mergeSeed = big.NewInt(0)
	if err := solveRing(buildMergeFixture(t, options)); err == nil {
		t.Fatal("zero-key merge solved under seed zero")
	}
}

func TestMergeRingRefusesZeroRingProgram(t *testing.T) {
	options := ringOptions()
	options.ringProgramID = big.NewInt(0)
	if err := solveRing(buildMergeFixture(t, options)); err == nil {
		t.Fatal("merge solved under ring program zero")
	}
}

func TestMergeRingRefusesWrongOutputRingDataHash(t *testing.T) {
	f := buildMergeFixture(t, ringOptions())
	f.outputRingDataHash = big.NewInt(0xBAD)
	f.publicInputPreimage[ringDataIndex] = f.outputRingDataHash
	f.rehash(t)
	if err := solveRing(f); err == nil {
		t.Fatal("solved under another carried ring data hash")
	}
}

func TestMergeRingZeroKeyDerivationsResistTheSecretZeroGuess(t *testing.T) {
	f := buildMergeFixture(t, zeroKeyOptions())
	firstNullifier := f.public.Nullifiers[0].(*big.Int)
	secretZero := big.NewInt(0)

	guessedBlinding, err := poseidon.Hash([]*big.Int{
		big.NewInt(mergeshared.MergeOutputBlindingDomainV1), secretZero, firstNullifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	realBlinding, err := poseidon.Hash([]*big.Int{
		big.NewInt(mergeshared.MergeOutputBlindingDomainV1), f.mergeSeed, firstNullifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	if guessedBlinding.Cmp(realBlinding) == 0 {
		t.Fatal("blinding computable from secret zero")
	}

	amount := big.NewInt(5 + 7)
	guessedCiphertext, err := protocol.MergeOutputCiphertext(
		secretZero, firstNullifier, fixtureCiphertextSalt, amount, fixtureMint,
	)
	if err != nil {
		t.Fatal(err)
	}
	for i := range guessedCiphertext {
		if guessedCiphertext[i].Cmp(f.outputCiphertext[i]) == 0 {
			t.Fatalf("ciphertext element %d computable from secret zero", i)
		}
	}

	guessedTxBlinding, err := protocol.PrivateTxBlinding(firstNullifier, secretZero)
	if err != nil {
		t.Fatal(err)
	}
	realTxBlinding, err := protocol.PrivateTxBlinding(firstNullifier, f.mergeSeed)
	if err != nil {
		t.Fatal(err)
	}
	if guessedTxBlinding.Cmp(realTxBlinding) == 0 {
		t.Fatal("tx blinding computable from secret zero")
	}

	const paddingSlot = 2
	guessedPadding, err := poseidon.Hash([]*big.Int{
		big.NewInt(mergeshared.MergeDummyNullifierDomain), secretZero, firstNullifier, big.NewInt(paddingSlot),
	})
	if err != nil {
		t.Fatal(err)
	}
	if guessedPadding.Cmp(f.public.Nullifiers[paddingSlot].(*big.Int)) == 0 {
		t.Fatal("padding nullifier computable from secret zero")
	}
}

func TestMergeRingRefusesAnotherSeedThanTheDerivations(t *testing.T) {
	f := buildMergeFixture(t, zeroKeyOptions())
	f.mergeSeed = new(big.Int).Add(f.mergeSeed, big.NewInt(1))
	if err := solveRing(f); err == nil {
		t.Fatal("solved under another seed than the published derivations")
	}
}

func TestMergeRingRefusesTamperedCiphertext(t *testing.T) {
	const ciphertextStart = 11
	for name, build := range map[string]func() mergeFixtureOptions{
		"zero key":    zeroKeyOptions,
		"nonzero key": ringOptions,
	} {
		for element := range mergeshared.MergeOutputCiphertextLen {
			t.Run(name, func(t *testing.T) {
				f := buildMergeFixture(t, build())
				index := ciphertextStart + element
				f.publicInputPreimage[index] = new(big.Int).Add(f.publicInputPreimage[index], big.NewInt(1))
				f.rehash(t)
				if err := solveRing(f); err == nil {
					t.Fatalf("ciphertext element %d replaced and solved", element)
				}
			})
		}
	}
}

func TestMergeRingBindsTheSalt(t *testing.T) {
	f := buildMergeFixture(t, zeroKeyOptions())
	f.outputCiphertextSalt = new(big.Int).Add(f.outputCiphertextSalt, big.NewInt(1))
	if err := solveRing(f); err == nil {
		t.Fatal("ciphertext under one salt solved under another")
	}
}

func TestMergeRingSupportsEveryWidth(t *testing.T) {
	for _, width := range mergeshared.SupportedInputCounts {
		options := zeroKeyOptions()
		options.inputCount = width
		if err := solveRing(buildMergeFixture(t, options)); err != nil {
			t.Fatalf("width %d: %v", width, err)
		}
	}
}

type ringVector struct {
	FirstNullifier    string   `json:"first_nullifier"`
	MergeSeed         string   `json:"merge_seed"`
	OutputBlinding    string   `json:"output_blinding"`
	OutputKey         string   `json:"output_key"`
	PrivateTxBlinding string   `json:"private_tx_blinding"`
	DummySlotIndex    int64    `json:"dummy_slot_index"`
	DummyNullifier    string   `json:"dummy_nullifier"`
	Salt              string   `json:"output_ciphertext_salt"`
	Amount            int64    `json:"output_amount"`
	Mint              string   `json:"output_mint"`
	Ciphertext        []string `json:"output_ciphertext"`
}

func TestMergeRingDerivationsMatchTheSharedVector(t *testing.T) {
	data, err := os.ReadFile("../../../../test-vectors/merge_ring.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector ringVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	hexField := func(value string) *big.Int {
		field, ok := new(big.Int).SetString(value, 16)
		if !ok {
			t.Fatalf("invalid vector field %q", value)
		}
		return field
	}
	seed, firstNullifier := hexField(vector.MergeSeed), hexField(vector.FirstNullifier)
	assertEqual := func(name string, got *big.Int, err error, want string) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if got.Cmp(hexField(want)) != 0 {
			t.Fatalf("%s: got %x want %s", name, got, want)
		}
	}
	blinding, err := poseidon.Hash([]*big.Int{big.NewInt(mergeshared.MergeOutputBlindingDomainV1), seed, firstNullifier})
	assertEqual("output blinding", blinding, err, vector.OutputBlinding)
	key, err := protocol.MergeOutputKey(seed, firstNullifier)
	assertEqual("output key", key, err, vector.OutputKey)
	txBlinding, err := protocol.PrivateTxBlinding(firstNullifier, seed)
	assertEqual("private tx blinding", txBlinding, err, vector.PrivateTxBlinding)
	dummy, err := poseidon.Hash([]*big.Int{
		big.NewInt(mergeshared.MergeDummyNullifierDomain), seed, firstNullifier, big.NewInt(vector.DummySlotIndex),
	})
	assertEqual("dummy nullifier", dummy, err, vector.DummyNullifier)

	var mint [32]byte
	hexField(vector.Mint).FillBytes(mint[:])
	ciphertext, err := protocol.MergeOutputCiphertext(
		seed, firstNullifier, hexField(vector.Salt), big.NewInt(vector.Amount), mint,
	)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range vector.Ciphertext {
		assertEqual("ciphertext", ciphertext[i], nil, want)
	}
}
