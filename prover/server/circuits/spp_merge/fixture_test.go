package merge_test

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	merge "zolana/prover/circuits/spp_merge"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
	"zolana/prover/prover-test/poseidon"
	"zolana/prover/prover-test/spp/protocol"
)

func buildValidWitness(t testing.TB) *merge.Circuit {
	t.Helper()
	return buildWitness(t, false)
}

func buildWitness(t testing.TB, eddsa bool) *merge.Circuit {
	t.Helper()
	return buildDefaultWitness(t, mergeFixtureOptions{eddsa: eddsa})
}

type mergeFixtureRail uint8

const (
	defaultFixtureRail mergeFixtureRail = iota
	ringFixtureRail
)

type mergeFixtureOptions struct {
	rail              mergeFixtureRail
	eddsa             bool
	asset             *big.Int
	ringProgramID     *big.Int
	inputRingData     []*big.Int
	outputRingData    *big.Int
	userSigningPkHash *big.Int
	allowDummyInputs  *big.Int
	// duplicateFirstInput fills input slot 1 with an exact copy of slot 0
	// (same UTXO, same paths, same nullifier); only the distinctness
	// constraint can reject the resulting witness.
	duplicateFirstInput bool
}

type mergeWitnessFixture struct {
	inputs []merge.Input
	output merge.Output

	asset               *big.Int
	ownerPkHash         *big.Int
	userNullifierPk     *big.Int
	userNullifierSecret *big.Int
	public              mergeshared.CommonPublicInputs
	userSigningPkHash   *big.Int
	outputRingDataHash  *big.Int
	ringProgramID       *big.Int
	publicInputHash     *big.Int
}

func buildDefaultWitness(t testing.TB, options mergeFixtureOptions) *merge.Circuit {
	t.Helper()
	options.rail = defaultFixtureRail
	return buildMergeFixture(t, options).defaultCircuit()
}

func buildRingWitness(t testing.TB, ringProgramID *big.Int) *merge.RingCircuit {
	t.Helper()
	return buildMergeFixture(t, mergeFixtureOptions{
		rail:           ringFixtureRail,
		ringProgramID:  ringProgramID,
		inputRingData:  []*big.Int{big.NewInt(0xD0), big.NewInt(0xD1)},
		outputRingData: big.NewInt(0xD2),
	}).ringCircuit()
}

func buildMergeFixture(t testing.TB, options mergeFixtureOptions) *mergeWitnessFixture {
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

	asset := big.NewInt(1)
	if options.asset != nil {
		asset = new(big.Int).Set(options.asset)
	}
	const numReal = 2
	amounts := []*big.Int{big.NewInt(5), big.NewInt(7)}
	blindings := []*big.Int{big.NewInt(0x1111), big.NewInt(0x2222)}
	ringData := []*big.Int{big.NewInt(0), big.NewInt(0)}
	if options.inputRingData != nil {
		if len(options.inputRingData) != numReal {
			t.Fatalf("input ring data count: got %d want %d", len(options.inputRingData), numReal)
		}
		ringData = options.inputRingData
	}
	outputRingData := big.NewInt(0)
	if options.outputRingData != nil {
		outputRingData = options.outputRingData
	}
	ringProgramID := big.NewInt(0)
	if options.rail == ringFixtureRail {
		if options.ringProgramID == nil {
			t.Fatal("ring fixture requires a ring program ID")
		}
		ringProgramID = options.ringProgramID
	}

	// Real input UTXOs and their state-tree leaves. Slot 0 is always real: the
	// output blinding derives from its blinding.
	inUtxos := make([]protocol.Utxo, numReal)
	inHashes := make([]*big.Int, numReal)
	stateEntries := map[uint64]*big.Int{}
	for i := 0; i < numReal; i++ {
		if options.duplicateFirstInput && i == 1 {
			inUtxos[i] = inUtxos[0]
			inHashes[i] = inHashes[0]
			continue
		}
		inUtxos[i] = protocol.Utxo{
			Domain:        big.NewInt(protocol.UtxoDomain),
			Owner:         userOwnerHash,
			Asset:         asset,
			Amount:        amounts[i],
			Blinding:      blindings[i],
			DataHash:      big.NewInt(0),
			RingDataHash:  ringData[i],
			RingProgramID: ringProgramID,
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
	if options.duplicateFirstInput {
		stateProofs[1] = stateProofs[0]
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
		if options.duplicateFirstInput && i == 1 {
			nullifiers[i] = nullifiers[0]
			nfWitnesses[i] = nfWitnesses[0]
			continue
		}
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

	// Merged output. The blinding is derived from the owner's nullifier secret
	// and the first real nullifier, mirroring the in-circuit derivation.
	outAmount := new(big.Int).Add(amounts[0], amounts[1])
	outBlinding, err := poseidon.Hash([]*big.Int{
		big.NewInt(mergeshared.MergeOutputBlindingDomainV1), nullifierSecret, nullifiers[0],
	})
	if err != nil {
		t.Fatal(err)
	}
	outUtxo := protocol.Utxo{
		Domain:        big.NewInt(protocol.UtxoDomain),
		Owner:         userOwnerHash,
		Asset:         asset,
		Amount:        outAmount,
		Blinding:      outBlinding,
		DataHash:      big.NewInt(0),
		RingDataHash:  outputRingData,
		RingProgramID: ringProgramID,
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

	userSigningPkHash := ownerKeyHash
	if options.userSigningPkHash != nil {
		userSigningPkHash = options.userSigningPkHash
	}

	// Dummy slots publish deterministic nullifiers derived from the owner's
	// nullifier secret and the first real nullifier, mirroring the in-circuit
	// derivation.
	dummyNullifier := func(slot int) *big.Int {
		nf, err := poseidon.Hash([]*big.Int{
			big.NewInt(mergeshared.MergeDummyNullifierDomain),
			nullifierSecret,
			nullifiers[0],
			big.NewInt(int64(slot)),
		})
		if err != nil {
			t.Fatal(err)
		}
		return nf
	}
	dummyNfWitnesses := make(map[int]protocol.NonInclusionWitness, merge.MergeInputs-numReal)
	for i := numReal; i < merge.MergeInputs; i++ {
		w, err := nfTree.NonInclusionWitness(dummyNullifier(i))
		if err != nil {
			t.Fatal(err)
		}
		dummyNfWitnesses[i] = w
	}

	// Public columns (real + dummy), reused verbatim in the public input hash.
	pubNullifiers := make([]*big.Int, merge.MergeInputs)
	pubUtxoRoots := make([]*big.Int, merge.MergeInputs)
	pubNfRoots := make([]*big.Int, merge.MergeInputs)
	for i := 0; i < merge.MergeInputs; i++ {
		if i < numReal {
			pubNullifiers[i] = nullifiers[i]
		} else {
			pubNullifiers[i] = dummyNullifier(i)
		}
		pubUtxoRoots[i] = stateRoot
		pubNfRoots[i] = nfRoot
	}

	allowDummyInputs := big.NewInt(1)
	if options.allowDummyInputs != nil {
		allowDummyInputs = options.allowDummyInputs
	}
	publicInputPreimage := []*big.Int{
		hashChain(t, pubNullifiers),
		outHash,
		hashChain(t, pubUtxoRoots),
		hashChain(t, pubNfRoots),
		privateTxHash,
		externalDataHash,
		allowDummyInputs,
	}
	switch options.rail {
	case defaultFixtureRail:
		publicInputPreimage = append(
			publicInputPreimage,
			userSigningPkHash,
		)
	case ringFixtureRail:
		publicInputPreimage = append(
			publicInputPreimage,
			outputRingData,
			ringProgramID,
		)
	default:
		t.Fatalf("unsupported merge fixture rail: %d", options.rail)
	}
	publicInputHash := hashChain(t, publicInputPreimage)

	inputs := mergeshared.NewInputs()
	public := mergeshared.NewCommonPublicInputs()
	public.ExternalDataHash = externalDataHash
	public.PrivateTxHash = privateTxHash
	public.OutputHash = outHash
	public.AllowDummyInputs = allowDummyInputs

	for i := 0; i < merge.MergeInputs; i++ {
		in := &inputs[i]
		public.Nullifiers[i] = pubNullifiers[i]
		public.UtxoTreeRoots[i] = pubUtxoRoots[i]
		public.NullifierTreeRoots[i] = pubNfRoots[i]
		if i < numReal {
			in.Domain = big.NewInt(protocol.UtxoDomain)
			in.Amount = amounts[i]
			in.Blinding = blindings[i]
			in.RingDataHash = ringData[i]
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
			in.RingDataHash = big.NewInt(0)
			zeroPath(in.StatePathElements)
			in.StatePathIndex = big.NewInt(0)
			w := dummyNfWitnesses[i]
			in.NullifierLowValue = w.LowValue
			in.NullifierNextValue = w.NextValue
			fillPath(in.NullifierLowPathElements, w.PathElements)
			in.NullifierLowPathIndex = big.NewInt(int64(w.LowIndex))
		}
	}
	if options.duplicateFirstInput {
		inputs[1] = inputs[0]
		inputs[1].Amount = amounts[1]
	}

	return &mergeWitnessFixture{
		inputs:              inputs,
		output:              merge.Output{RingDataHash: outputRingData},
		asset:               asset,
		ownerPkHash:         ownerKeyHash,
		userNullifierPk:     userNullifierPk,
		userNullifierSecret: nullifierSecret,
		public:              public,
		userSigningPkHash:   userSigningPkHash,
		outputRingDataHash:  outputRingData,
		ringProgramID:       ringProgramID,
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
	assignment.CommonPublicInputs = f.public
	assignment.UserSigningPkHash = f.userSigningPkHash
	assignment.PublicInputHash = f.publicInputHash
	return assignment
}

func (f *mergeWitnessFixture) ringCircuit() *merge.RingCircuit {
	assignment := merge.NewMergeRingCircuit()
	assignment.Inputs = f.inputs
	assignment.Output = f.output
	assignment.Asset = f.asset
	assignment.OwnerPkHash = f.ownerPkHash
	assignment.UserNullifierPk = f.userNullifierPk
	assignment.UserNullifierSecret = f.userNullifierSecret
	assignment.CommonPublicInputs = f.public
	assignment.OutputRingDataHash = f.outputRingDataHash
	assignment.RingProgramID = f.ringProgramID
	assignment.PublicInputHash = f.publicInputHash
	return assignment
}

func hashChain(t testing.TB, in []*big.Int) *big.Int {
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
