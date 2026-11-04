package merge_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	merge "github.com/helius-labs/zolana/prover/server/circuits/spp_merge"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/poseidon"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
)

var (
	fixtureRingV2Program = big.NewInt(0xC0FFEE)
	fixtureMergeSeed     = big.NewInt(0x5EED)
)

func ringV2Options() mergeFixtureOptions {
	return mergeFixtureOptions{
		rail:           ringV2FixtureRail,
		ringProgramID:  fixtureRingV2Program,
		inputRingData:  []*big.Int{big.NewInt(0xD0), big.NewInt(0xD1)},
		outputRingData: big.NewInt(0xD2),
	}
}

func zeroKeyOptions() mergeFixtureOptions {
	options := ringV2Options()
	options.nullifierSecret = big.NewInt(0)
	options.mergeSeed = fixtureMergeSeed
	return options
}

func solveRingV2(f *mergeWitnessFixture) error {
	return test.IsSolved(merge.NewMergeRingV2Circuit(len(f.inputs)), f.ringV2Circuit(), ecc.BN254.ScalarField())
}

func (f *mergeWitnessFixture) rehash(t *testing.T) {
	t.Helper()
	f.publicInputHash = hashChain4(t, f.publicInputPreimage)
}

// Tail positions after the seven prefix elements.
const (
	ringV2RingDataIndex = 7
	ringV2OwnerIndex    = 9
)

func TestMergeRingV2NonzeroKeyPublishesNoOwner(t *testing.T) {
	f := buildMergeFixture(t, ringV2Options())
	if f.publishedOwner.Sign() != 0 {
		t.Fatalf("published owner %v", f.publishedOwner)
	}
	if err := solveRingV2(f); err != nil {
		t.Fatalf("nonzero-key merge: %v", err)
	}
}

func TestMergeRingV2ZeroKeyPublishesItsOwner(t *testing.T) {
	f := buildMergeFixture(t, zeroKeyOptions())
	if f.publishedOwner.Cmp(f.ownerPkHash) != 0 {
		t.Fatalf("published owner %v want %v", f.publishedOwner, f.ownerPkHash)
	}
	if err := solveRingV2(f); err != nil {
		t.Fatalf("zero-key merge: %v", err)
	}
}

// A proof published under another owner never matches SPP's signer hash.
func TestMergeRingV2RefusesAnyOtherPublishedOwner(t *testing.T) {
	for name, build := range map[string]func() mergeFixtureOptions{
		"zero key":    zeroKeyOptions,
		"nonzero key": ringV2Options,
	} {
		t.Run(name, func(t *testing.T) {
			f := buildMergeFixture(t, build())
			other := new(big.Int).Add(f.publishedOwner, big.NewInt(1))
			f.publishedOwner = other
			f.publicInputPreimage[ringV2OwnerIndex] = other
			f.rehash(t)
			if err := solveRingV2(f); err == nil {
				t.Fatal("solved under another published owner")
			}
		})
	}
}

// Publishing zero under a zero key would let an outsider who knows the opening
// merge with no signer.
func TestMergeRingV2RefusesZeroKeyWithoutPublishedOwner(t *testing.T) {
	options := zeroKeyOptions()
	options.publishedOwner = big.NewInt(0)
	if err := solveRingV2(buildMergeFixture(t, options)); err == nil {
		t.Fatal("zero-key merge solved with no published owner")
	}
}

func TestMergeRingV2RefusesZeroOwnerUnderZeroKey(t *testing.T) {
	options := zeroKeyOptions()
	options.ownerKeyHash = big.NewInt(0)
	if err := solveRingV2(buildMergeFixture(t, options)); err == nil {
		t.Fatal("zero-key merge solved for a zero owner")
	}
}

func TestMergeRingV2RefusesZeroSeedUnderZeroKey(t *testing.T) {
	options := zeroKeyOptions()
	options.mergeSeed = big.NewInt(0)
	if err := solveRingV2(buildMergeFixture(t, options)); err == nil {
		t.Fatal("zero-key merge solved under seed zero")
	}
}

func TestMergeRingV2RefusesZeroRingProgram(t *testing.T) {
	options := ringV2Options()
	options.ringProgramID = big.NewInt(0)
	if err := solveRingV2(buildMergeFixture(t, options)); err == nil {
		t.Fatal("merge solved under ring program zero")
	}
}

func TestMergeRingV2RefusesWrongOutputRingDataHash(t *testing.T) {
	f := buildMergeFixture(t, ringV2Options())
	f.outputRingDataHash = big.NewInt(0xBAD)
	f.publicInputPreimage[ringV2RingDataIndex] = f.outputRingDataHash
	f.rehash(t)
	if err := solveRingV2(f); err == nil {
		t.Fatal("solved under another carried ring data hash")
	}
}

// Under a zero key the derivations come from the seed, so an observer holding
// public data and secret zero matches none of them.
func TestMergeRingV2ZeroKeyDerivationsResistTheSecretZeroGuess(t *testing.T) {
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

// The seed is the only secret on the zero-key path, and every derived value
// must follow it: the fixture publishes values for one seed, the witness names
// another.
func TestMergeRingV2RefusesAnotherSeedThanTheDerivations(t *testing.T) {
	f := buildMergeFixture(t, zeroKeyOptions())
	f.mergeSeed = new(big.Int).Add(f.mergeSeed, big.NewInt(1))
	if err := solveRingV2(f); err == nil {
		t.Fatal("solved under another seed than the published derivations")
	}
}

func TestMergeRingV2RefusesTamperedCiphertext(t *testing.T) {
	const ciphertextStart = 11
	for name, build := range map[string]func() mergeFixtureOptions{
		"zero key":    zeroKeyOptions,
		"nonzero key": ringV2Options,
	} {
		for element := range mergeshared.MergeOutputCiphertextLen {
			t.Run(name, func(t *testing.T) {
				f := buildMergeFixture(t, build())
				index := ciphertextStart + element
				f.publicInputPreimage[index] = new(big.Int).Add(f.publicInputPreimage[index], big.NewInt(1))
				f.rehash(t)
				if err := solveRingV2(f); err == nil {
					t.Fatalf("ciphertext element %d replaced and solved", element)
				}
			})
		}
	}
}

func TestMergeRingV2BindsTheSalt(t *testing.T) {
	f := buildMergeFixture(t, zeroKeyOptions())
	f.outputCiphertextSalt = new(big.Int).Add(f.outputCiphertextSalt, big.NewInt(1))
	if err := solveRingV2(f); err == nil {
		t.Fatal("ciphertext under one salt solved under another")
	}
}

func TestMergeRingV2SupportsEveryWidth(t *testing.T) {
	for _, width := range mergeshared.SupportedInputCounts {
		options := zeroKeyOptions()
		options.inputCount = width
		if err := solveRingV2(buildMergeFixture(t, options)); err != nil {
			t.Fatalf("width %d: %v", width, err)
		}
	}
}
