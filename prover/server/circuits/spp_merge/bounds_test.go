package merge_test

import (
	"crypto/elliptic"
	"math/big"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	merge "zolana/prover/circuits/spp_merge"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
	transaction "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/hintattack"
	"zolana/prover/prover-test/poseidon"
	"zolana/prover/prover-test/spp/protocol"
)

var (
	ringMergeCSOnce sync.Once
	ringMergeCS     constraint.ConstraintSystem
	ringMergeCSErr  error
)

func compiledRingMerge(t *testing.T) constraint.ConstraintSystem {
	t.Helper()
	ringMergeCSOnce.Do(func() {
		ringMergeCS, ringMergeCSErr = frontend.Compile(
			ecc.BN254.ScalarField(),
			r1cs.NewBuilder,
			merge.NewMergeRingCircuit(defaultFixtureInputs),
			frontend.WithCompressThreshold(300),
		)
	})
	if ringMergeCSErr != nil {
		t.Fatalf("compile: %v", ringMergeCSErr)
	}
	return ringMergeCS
}

func compiledHintNames(t *testing.T, cs constraint.ConstraintSystem) []string {
	t.Helper()
	system, ok := cs.(*csbn254.R1CS)
	if !ok {
		t.Fatalf("unexpected constraint system %T", cs)
	}
	names := make([]string, 0, len(system.MHintsDependencies))
	for _, name := range system.MHintsDependencies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func powerOfTwo(bits int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(bits))
}

func offset(v *big.Int, delta int64) *big.Int {
	return new(big.Int).Add(v, big.NewInt(delta))
}

func lowBytes(v *big.Int, n int) []byte {
	reduced := new(big.Int).Mod(v, powerOfTwo(8*n))
	return reduced.FillBytes(make([]byte, n))
}

func fixtureMintChunks() [mergeshared.MintChunkCount]*big.Int {
	mint := fixtureMint()
	return [mergeshared.MintChunkCount]*big.Int{
		new(big.Int).SetBytes(mint[:mergeshared.MintHeadChunkBytes]),
		new(big.Int).SetBytes(mint[mergeshared.MintHeadChunkBytes:]),
	}
}

type boundsWitness struct {
	rail       mergeFixtureRail
	amounts    [2]*big.Int
	mintChunks [mergeshared.MintChunkCount]*big.Int
}

func (b boundsWitness) plaintext(amount *big.Int) []byte {
	plaintext := lowBytes(amount, mergeshared.MergeAmountBytes)
	plaintext = append(plaintext, lowBytes(b.mintChunks[0], mergeshared.MintHeadChunkBytes)...)
	return append(plaintext, lowBytes(b.mintChunks[1], mergeshared.MintTailChunkBytes)...)
}

func (b boundsWitness) fixture(t *testing.T) *mergeWitnessFixture {
	t.Helper()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	hash := func(inputs ...*big.Int) *big.Int {
		t.Helper()
		h, err := poseidon.Hash(inputs)
		check(err)
		return h
	}

	curve := elliptic.P256()
	ownerX, ownerY := curve.ScalarBaseMult(leftPad32(big.NewInt(11)))
	ownerKeyHash, err := protocol.OwnerPkField(elliptic.MarshalCompressed(curve, ownerX, ownerY))
	check(err)
	nullifierSecret := big.NewInt(19)
	userNullifierPk, err := protocol.NullifierPk(nullifierSecret)
	check(err)
	userOwnerHash, err := protocol.OwnerHash(ownerKeyHash, userNullifierPk)
	check(err)
	asset, err := protocol.HashChain(b.mintChunks[:])
	check(err)

	ringProgramID := big.NewInt(0)
	inputRingData := [2]*big.Int{big.NewInt(0), big.NewInt(0)}
	outputRingData := big.NewInt(0)
	if b.rail == ringFixtureRail {
		ringProgramID = big.NewInt(0x5A0E)
		inputRingData = [2]*big.Int{big.NewInt(0xD0), big.NewInt(0xD1)}
		outputRingData = big.NewInt(0xD2)
	}

	blindings := [2]*big.Int{big.NewInt(0x1111), big.NewInt(0x2222)}
	inHashes := make([]*big.Int, len(b.amounts))
	stateEntries := map[uint64]*big.Int{}
	for i := range inHashes {
		inHashes[i] = mergeUtxoHash(t, protocol.Utxo{
			Domain:        big.NewInt(protocol.UtxoDomain),
			Owner:         userOwnerHash,
			Asset:         asset,
			Amount:        b.amounts[i],
			Blinding:      blindings[i],
			DataHash:      big.NewInt(0),
			RingDataHash:  inputRingData[i],
			RingProgramID: ringProgramID,
		}, fixtureInputTreeID)
		stateEntries[uint64(i)] = inHashes[i]
	}
	stateRoot, stateProofs, err := protocol.BuildSparseStateTree(stateEntries)
	check(err)

	nfTree, err := protocol.NewNullifierTree()
	check(err)
	nullifiers := make([]*big.Int, len(inHashes))
	nfWitnesses := make([]protocol.NonInclusionWitness, len(inHashes))
	for i := range nullifiers {
		nullifiers[i], err = protocol.Nullifier(inHashes[i], blindings[i], nullifierSecret)
		check(err)
		nfWitnesses[i], err = nfTree.NonInclusionWitness(nullifiers[i])
		check(err)
	}

	outAmount := new(big.Int).Add(b.amounts[0], b.amounts[1])
	outBlinding := hash(big.NewInt(mergeshared.MergeOutputBlindingDomainV1), nullifierSecret, nullifiers[0])
	var envelope *hostEnvelope
	if b.rail == defaultFixtureRail {
		encrypted := honestEnvelope(t, b.plaintext(outAmount), nullifiers[0])
		envelope = &encrypted
		outBlinding = hash(big.NewInt(mergeshared.MergeDerivedBlindingDomain), encrypted.sharedSecret)
	}
	outHash := mergeUtxoHash(t, protocol.Utxo{
		Domain:        big.NewInt(protocol.UtxoDomain),
		Owner:         userOwnerHash,
		Asset:         asset,
		Amount:        outAmount,
		Blinding:      outBlinding,
		DataHash:      big.NewInt(0),
		RingDataHash:  outputRingData,
		RingProgramID: ringProgramID,
	}, fixtureOutputTreeID)

	inputCount := defaultFixtureInputs
	inputHashChain := make([]*big.Int, inputCount)
	addressNullifiers := make([]*big.Int, inputCount)
	pubNullifiers := make([]*big.Int, inputCount)
	for i := range inputHashChain {
		inputHashChain[i] = big.NewInt(0)
		addressNullifiers[i] = big.NewInt(0)
		if i < len(inHashes) {
			inputHashChain[i] = inHashes[i]
			pubNullifiers[i] = nullifiers[i]
		} else {
			pubNullifiers[i] = hash(big.NewInt(mergeshared.MergeDummyNullifierDomain), nullifierSecret, nullifiers[0], big.NewInt(int64(i)))
		}
	}
	privateTxBlinding, err := protocol.PrivateTxBlinding(nullifiers[0], nullifierSecret)
	check(err)
	privateTxHash, err := protocol.PrivateTxHash(inputHashChain, []*big.Int{outHash}, addressNullifiers, privateTxBlinding)
	check(err)

	public := mergeshared.NewCommonPublicInputs(inputCount)
	public.ExternalDataHash = big.NewInt(0xABCDEF)
	public.PrivateTxHash = privateTxHash
	public.OutputHash = outHash
	public.AllowDummyInputs = big.NewInt(1)
	public.OutputTreeID = big.NewInt(fixtureOutputTreeID)
	for k, id := range fixtureSlotTreeIDs() {
		public.TreeSlots[k] = transaction.TreeSlot{ID: id, UtxoRoot: stateRoot, NullifierRoot: nfTree.Root()}
	}

	inputs := mergeshared.NewInputs(inputCount)
	for i := range inputs {
		in := &inputs[i]
		public.Nullifiers[i] = pubNullifiers[i]
		in.TreeSlot = big.NewInt(0)
		if i < len(inHashes) {
			proof := stateProofs[uint64(i)]
			in.Domain = big.NewInt(protocol.UtxoDomain)
			in.Amount = b.amounts[i]
			in.Blinding = blindings[i]
			in.RingDataHash = inputRingData[i]
			fillPath(in.StatePathElements, proof.PathElements)
			in.StatePathIndex = big.NewInt(int64(proof.PathIndex))
			in.NullifierLowValue = nfWitnesses[i].LowValue
			in.NullifierNextValue = nfWitnesses[i].NextValue
			fillPath(in.NullifierLowPathElements, nfWitnesses[i].PathElements)
			in.NullifierLowPathIndex = big.NewInt(int64(nfWitnesses[i].LowIndex))
			continue
		}
		w, err := nfTree.NonInclusionWitness(pubNullifiers[i])
		check(err)
		in.Domain = big.NewInt(protocol.DummyDomain)
		in.Amount = big.NewInt(0)
		in.Blinding = big.NewInt(0)
		in.RingDataHash = big.NewInt(0)
		zeroPath(in.StatePathElements)
		in.StatePathIndex = big.NewInt(0)
		in.NullifierLowValue = w.LowValue
		in.NullifierNextValue = w.NextValue
		fillPath(in.NullifierLowPathElements, w.PathElements)
		in.NullifierLowPathIndex = big.NewInt(int64(w.LowIndex))
	}

	f := &mergeWitnessFixture{
		inputs:              inputs,
		output:              merge.Output{RingDataHash: outputRingData},
		mintChunks:          [mergeshared.MintChunkCount]frontend.Variable{b.mintChunks[0], b.mintChunks[1]},
		envelope:            envelope,
		ownerPkHash:         ownerKeyHash,
		userNullifierPk:     userNullifierPk,
		userNullifierSecret: nullifierSecret,
		public:              public,
		userSigningPkHash:   ownerKeyHash,
		outputRingDataHash:  outputRingData,
		ringProgramID:       ringProgramID,
	}
	if b.rail == ringFixtureRail {
		refreshRingPublicInputHash(t, f)
	} else {
		refreshDefaultPublicInputHash(t, f)
	}
	return f
}

func (b boundsWitness) solve(t *testing.T) error {
	t.Helper()
	f := b.fixture(t)
	if b.rail == ringFixtureRail {
		return solveMerge(t, compiledRingMerge(t), f.ringCircuit())
	}
	return solveMerge(t, compiledDefaultMerge(t), f.defaultCircuit())
}

func assertBound(t *testing.T, err error, accepted bool) {
	t.Helper()
	switch {
	case accepted && err != nil:
		t.Fatalf("rejected a value inside the bound: %v", err)
	case !accepted:
		hintattack.RequireConstraintRejection(t, err)
	}
}

func TestMergeOutputAmountBound(t *testing.T) {
	half := powerOfTwo(63)
	maxAmount := offset(powerOfTwo(64), -1)
	for _, rail := range []struct {
		name string
		rail mergeFixtureRail
	}{
		{"default", defaultFixtureRail},
		{"ring", ringFixtureRail},
	} {
		t.Run(rail.name, func(t *testing.T) {
			for _, row := range []struct {
				name     string
				amounts  [2]*big.Int
				accepted bool
			}{
				{"inputs sum to 2^64 - 1", [2]*big.Int{half, offset(half, -1)}, true},
				{"inputs sum to 2^64", [2]*big.Int{half, half}, false},
				{"both inputs at 2^64 - 1", [2]*big.Int{maxAmount, maxAmount}, false},
			} {
				t.Run(row.name, func(t *testing.T) {
					start := time.Now()
					err := boundsWitness{rail: rail.rail, amounts: row.amounts, mintChunks: fixtureMintChunks()}.solve(t)
					assertBound(t, err, row.accepted)
					t.Logf("solved in %s", time.Since(start).Round(time.Millisecond))
				})
			}
		})
	}
}

func TestMergeMintChunkBound(t *testing.T) {
	honest := fixtureMintChunks()
	headBound := powerOfTwo(8 * mergeshared.MintHeadChunkBytes)
	tailBound := powerOfTwo(8 * mergeshared.MintTailChunkBytes)
	for _, row := range []struct {
		name     string
		chunks   [mergeshared.MintChunkCount]*big.Int
		accepted bool
	}{
		{"head at 2^248 - 1", [2]*big.Int{offset(headBound, -1), honest[1]}, true},
		{"head at 2^248", [2]*big.Int{headBound, honest[1]}, false},
		{"head 2^248 above the honest chunk", [2]*big.Int{new(big.Int).Add(honest[0], headBound), honest[1]}, false},
		{"tail at 2^8 - 1", [2]*big.Int{honest[0], offset(tailBound, -1)}, true},
		{"tail at 2^8", [2]*big.Int{honest[0], tailBound}, false},
		{"tail 2^8 above the honest chunk", [2]*big.Int{honest[0], new(big.Int).Add(honest[1], tailBound)}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := boundsWitness{
				rail:       defaultFixtureRail,
				amounts:    [2]*big.Int{big.NewInt(5), big.NewInt(7)},
				mintChunks: row.chunks,
			}.solve(t)
			assertBound(t, err, row.accepted)
		})
	}
}

func TestMergeRingRejectsHintAttacks(t *testing.T) {
	start := time.Now()
	cs := compiledRingMerge(t)
	assignment := buildRingWitness(t, big.NewInt(0x5A0E))
	t.Logf("compiled and built the witness in %s: %d constraints", time.Since(start).Round(time.Millisecond), cs.GetNbConstraints())
	t.Logf("hints: %v", compiledHintNames(t, cs))
	hintattack.RunHintAttacks(t, cs, func(opts ...solver.Option) error {
		return solveMerge(t, cs, assignment, opts...)
	})
	t.Logf("total %s", time.Since(start).Round(time.Millisecond))
}
