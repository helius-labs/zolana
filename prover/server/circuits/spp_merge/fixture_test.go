package merge_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	merge "github.com/helius-labs/zolana/prover/server/circuits/spp_merge"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover-test/poseidon"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func buildValidWitness(t testing.TB) *merge.Circuit {
	t.Helper()
	return buildWitness(t)
}

func buildWitness(t testing.TB) *merge.Circuit {
	t.Helper()
	return buildDefaultWitness(t, mergeFixtureOptions{})
}

type mergeFixtureRail uint8

const (
	defaultFixtureRail mergeFixtureRail = iota
	ringFixtureRail
)

// defaultFixtureInputs is the merge shape the fixtures build. Every supported
// count shares the same per-slot constraints; the wider shapes are covered by
// the compile smoke test and their own proving keys.
const defaultFixtureInputs = 24

type mergeFixtureOptions struct {
	inputCount        int
	externalDataHash  *big.Int
	rail              mergeFixtureRail
	ringProgramID     *big.Int
	inputRingData     []*big.Int
	outputRingData    *big.Int
	userSigningPkHash *big.Int
	allowDummyInputs  *big.Int
	// duplicateFirstInput fills input slot 1 with an exact copy of slot 0
	// (same UTXO, same paths, same nullifier); only the distinctness
	// constraint can reject the resulting witness.
	duplicateFirstInput bool
	// inputSlot places input 1 in that tree slot: hashed under the slot's tree
	// id and the sole leaf of a second state tree published as the slot's root.
	inputSlot int
	// outputNullifierPk publishes the merged output under another nullifier key.
	outputNullifierPk *big.Int
}

// Slot 0's tree id is fixtureInputTreeID; fixtureOutputTreeID differs from
// every slot id so a swapped input/output id is caught.
const (
	fixtureInputTreeID  = 7
	fixtureOutputTreeID = 11
)

// fixtureMint has a nonzero last byte so both hash_bytes_32 chunks matter.
var fixtureMint = [32]byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

// fixtureCiphertextSalt is a 16-byte salt, as the instruction data carries.
var fixtureCiphertextSalt = new(big.Int).SetBytes([]byte{
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
})

// fixtureSlotTreeIDs returns InputTrees distinct tree ids, slot 0 = fixtureInputTreeID.
func fixtureSlotTreeIDs() []*big.Int {
	ids := []int64{fixtureInputTreeID, 17, 19, 23, 29}
	out := make([]*big.Int, mergeshared.InputTrees)
	for k := range out {
		out[k] = big.NewInt(ids[k])
	}
	return out
}

// fixtureTreeSlots pairs each slot's id with its two roots.
func fixtureTreeSlots(ids, utxoRoots, nullifierRoots []*big.Int) []protocol.TreeSlot {
	slots := make([]protocol.TreeSlot, len(ids))
	for k := range ids {
		slots[k] = protocol.TreeSlot{ID: ids[k], UtxoRoot: utxoRoots[k], NullifierRoot: nullifierRoots[k]}
	}
	return slots
}

// publicTreeSlots reads the assigned circuit slots back as host values.
func publicTreeSlots(slots []transaction.TreeSlot) []protocol.TreeSlot {
	out := make([]protocol.TreeSlot, len(slots))
	for k, slot := range slots {
		out[k] = protocol.TreeSlot{
			ID:            slot.ID.(*big.Int),
			UtxoRoot:      slot.UtxoRoot.(*big.Int),
			NullifierRoot: slot.NullifierRoot.(*big.Int),
		}
	}
	return out
}

// mergeUtxoHash hashes u under the raw id of the tree that holds it.
func mergeUtxoHash(t testing.TB, u protocol.Utxo, treeID int64) *big.Int {
	t.Helper()
	return spptest.MustUtxoHash(t, u, big.NewInt(treeID))
}

type mergeWitnessFixture struct {
	inputs []merge.Input
	output merge.Output

	mintChunks          [2]*big.Int
	ownerPkHash         *big.Int
	userNullifierPk     *big.Int
	userNullifierSecret *big.Int
	public              mergeshared.CommonPublicInputs
	userSigningPkHash   *big.Int
	outputRingDataHash  *big.Int
	ringProgramID       *big.Int
	memberRegistryRoot  *big.Int
	registeredCtHash    *big.Int
	memberRecord        registry.RecordOpening
	outputCiphertext    []*big.Int
	publicInputPreimage []*big.Int
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
		inputRingData:  []*big.Int{big.NewInt(0xD0), big.NewInt(0xD0)},
		outputRingData: big.NewInt(0xD0),
	}).ringCircuit()
}

func buildMergeFixture(t testing.TB, options mergeFixtureOptions) *mergeWitnessFixture {
	t.Helper()
	inputCount := options.inputCount
	if inputCount == 0 {
		inputCount = defaultFixtureInputs
	}
	// Owner identity: Solana signing key + shared nullifier secret.
	var solanaPubkey [32]byte
	solanaPubkey[31] = 0x2a
	ownerKeyHash, err := protocol.SolanaPkField(solanaPubkey)
	if err != nil {
		t.Fatal(err)
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

	asset, err := protocol.AssetField(fixtureMint)
	if err != nil {
		t.Fatal(err)
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
	if options.inputSlot < 0 || options.inputSlot >= mergeshared.InputTrees {
		t.Fatalf("input slot %d out of range", options.inputSlot)
	}
	treeIDs := fixtureSlotTreeIDs()
	inputSlots := []int{0, options.inputSlot}
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
		h := mergeUtxoHash(t, inUtxos[i], treeIDs[inputSlots[i]].Int64())
		inHashes[i] = h
		stateEntries[uint64(i)] = h
	}
	// Every slot publishes the slot-0 state root under its own tree id. An
	// input placed in another slot is instead the sole leaf of a second tree
	// published as that slot's root.
	if options.inputSlot != 0 {
		delete(stateEntries, 1)
	}
	stateRoot, stateProofs, err := protocol.BuildSparseStateTree(stateEntries)
	if err != nil {
		t.Fatal(err)
	}
	slotRoots := make([]*big.Int, mergeshared.InputTrees)
	for k := range slotRoots {
		slotRoots[k] = stateRoot
	}
	if options.inputSlot != 0 {
		otherRoot, otherProofs, err := protocol.BuildSparseStateTree(map[uint64]*big.Int{1: inHashes[1]})
		if err != nil {
			t.Fatal(err)
		}
		stateProofs[1] = otherProofs[1]
		slotRoots[options.inputSlot] = otherRoot
	}
	if options.duplicateFirstInput {
		stateProofs[1] = stateProofs[0]
	}

	// Empty nullifier tree: every real nullifier is bracketed by the sentinel.
	nfTree, err := protocol.NewNullifierTree()
	if err != nil {
		t.Fatal(err)
	}
	slotNullifierRoots := make([]*big.Int, mergeshared.InputTrees)
	for k := range slotNullifierRoots {
		slotNullifierRoots[k] = nfTree.Root()
	}
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
		inputNullifierTree := nfTree
		if inputSlots[i] != 0 {
			inputNullifierTree, err = protocol.NewNullifierTree()
			if err != nil {
				t.Fatal(err)
			}
			if err := inputNullifierTree.Insert(big.NewInt(int64(inputSlots[i]))); err != nil {
				t.Fatal(err)
			}
			slotNullifierRoots[inputSlots[i]] = inputNullifierTree.Root()
		}
		w, err := inputNullifierTree.NonInclusionWitness(nf)
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
	outputOwnerHash := userOwnerHash
	if options.outputNullifierPk != nil {
		outputOwnerHash, err = protocol.OwnerHash(ownerKeyHash, options.outputNullifierPk)
		if err != nil {
			t.Fatal(err)
		}
	}
	outUtxo := protocol.Utxo{
		Domain:        big.NewInt(protocol.UtxoDomain),
		Owner:         outputOwnerHash,
		Asset:         asset,
		Amount:        outAmount,
		Blinding:      outBlinding,
		DataHash:      big.NewInt(0),
		RingDataHash:  outputRingData,
		RingProgramID: ringProgramID,
	}
	outHash := mergeUtxoHash(t, outUtxo, fixtureOutputTreeID)
	outputCiphertext, err := protocol.MergeOutputCiphertext(
		nullifierSecret, nullifiers[0], fixtureCiphertextSalt, outAmount, fixtureMint,
	)
	if err != nil {
		t.Fatal(err)
	}

	externalDataHash := options.externalDataHash
	if externalDataHash == nil {
		externalDataHash = big.NewInt(0xABCDEF)
	}

	// private_tx_hash over the input/output hash chains (dummies contribute 0).
	inputHashChainInputs := make([]*big.Int, inputCount)
	for i := 0; i < inputCount; i++ {
		if i < numReal {
			inputHashChainInputs[i] = inHashes[i]
		} else {
			inputHashChainInputs[i] = big.NewInt(0)
		}
	}
	addressNullifiers := make([]*big.Int, inputCount)
	for i := range addressNullifiers {
		addressNullifiers[i] = big.NewInt(0)
	}
	privateTxBlinding, err := protocol.PrivateTxBlinding(nullifiers[0], nullifierSecret)
	if err != nil {
		t.Fatal(err)
	}
	privateTxHash, err := protocol.PrivateTxHash(
		inputHashChainInputs,
		[]*big.Int{outHash},
		addressNullifiers,
		privateTxBlinding,
	)
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
	dummyNfWitnesses := make(map[int]protocol.NonInclusionWitness, inputCount-numReal)
	for i := numReal; i < inputCount; i++ {
		w, err := nfTree.NonInclusionWitness(dummyNullifier(i))
		if err != nil {
			t.Fatal(err)
		}
		dummyNfWitnesses[i] = w
	}

	// Public columns (real + dummy), reused verbatim in the public input hash.
	pubNullifiers := make([]*big.Int, inputCount)
	for i := 0; i < inputCount; i++ {
		if i < numReal {
			pubNullifiers[i] = nullifiers[i]
		} else {
			pubNullifiers[i] = dummyNullifier(i)
		}
	}

	allowDummyInputs := big.NewInt(1)
	if options.allowDummyInputs != nil {
		allowDummyInputs = options.allowDummyInputs
	}
	outputTreeID := big.NewInt(fixtureOutputTreeID)
	treeSlots := fixtureTreeSlots(treeIDs, slotRoots, slotNullifierRoots)
	var memberRoot, registeredCtHash *big.Int
	var memberRecord registry.RecordOpening
	if options.rail == ringFixtureRail {
		registeredCtHash = big.NewInt(0xC7)
		members := spptest.NewMemberRegistry(t, registry.Height)
		members.RegisterKey(t, ownerKeyHash, userNullifierPk, registeredCtHash)
		memberRoot = members.Root()
		opened := members.Opening(ownerKeyHash)
		memberRecord.Next = opened.Record.Next
		memberRecord.Lists = opened.Record.Lists
		memberRecord.EscrowKey = opened.Record.EscrowKey
		memberRecord.Index = opened.Index
		for i, value := range opened.Path {
			memberRecord.Path[i] = new(big.Int).Set(&value)
		}
	}
	publicInputPreimage := []*big.Int{
		spptest.MustRightHashChain4(t, pubNullifiers),
		outHash,
		spptest.MustTreeSlotsHashChain(t, treeSlots),
		outputTreeID,
		privateTxHash,
		externalDataHash,
		allowDummyInputs,
	}
	switch options.rail {
	case defaultFixtureRail:
		publicInputPreimage = append(
			publicInputPreimage,
			userSigningPkHash,
			userNullifierPk,
		)
	case ringFixtureRail:
		publicInputPreimage = append(
			publicInputPreimage,
			outputRingData,
			ringProgramID,
			memberRoot,
		)
	default:
		t.Fatalf("unsupported merge fixture rail: %d", options.rail)
	}
	publicInputPreimage = append(publicInputPreimage, fixtureCiphertextSalt)
	publicInputPreimage = append(publicInputPreimage, outputCiphertext...)
	publicInputHash := hashChain4(t, publicInputPreimage)

	inputs := mergeshared.NewInputs(inputCount)
	public := mergeshared.NewCommonPublicInputs(inputCount)
	public.ExternalDataHash = externalDataHash
	public.PrivateTxHash = privateTxHash
	public.OutputHash = outHash
	public.AllowDummyInputs = allowDummyInputs
	public.OutputTreeID = outputTreeID
	public.OutputCiphertextSalt = fixtureCiphertextSalt
	for k, slot := range treeSlots {
		public.TreeSlots[k] = transaction.TreeSlot{
			ID:            slot.ID,
			UtxoRoot:      slot.UtxoRoot,
			NullifierRoot: slot.NullifierRoot,
		}
	}

	for i := 0; i < inputCount; i++ {
		in := &inputs[i]
		public.Nullifiers[i] = pubNullifiers[i]
		in.TreeSlot = big.NewInt(0)
		if i < numReal {
			in.TreeSlot = big.NewInt(int64(inputSlots[i]))
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
		mintChunks:          protocol.MintChunks(fixtureMint),
		ownerPkHash:         ownerKeyHash,
		userNullifierPk:     userNullifierPk,
		userNullifierSecret: nullifierSecret,
		public:              public,
		userSigningPkHash:   userSigningPkHash,
		outputRingDataHash:  outputRingData,
		ringProgramID:       ringProgramID,
		memberRegistryRoot:  memberRoot,
		registeredCtHash:    registeredCtHash,
		memberRecord:        memberRecord,
		outputCiphertext:    outputCiphertext,
		publicInputPreimage: publicInputPreimage,
		publicInputHash:     publicInputHash,
	}
}

func (f *mergeWitnessFixture) mintChunkVariables() [2]frontend.Variable {
	return [2]frontend.Variable{f.mintChunks[0], f.mintChunks[1]}
}

func (f *mergeWitnessFixture) defaultCircuit() *merge.Circuit {
	assignment := merge.NewMergeCircuit(len(f.inputs))
	assignment.Inputs = f.inputs
	assignment.Output = f.output
	assignment.MintChunks = f.mintChunkVariables()
	assignment.OwnerPkHash = f.ownerPkHash
	assignment.UserNullifierPk = f.userNullifierPk
	assignment.UserNullifierSecret = f.userNullifierSecret
	assignment.CommonPublicInputs = f.public
	assignment.UserSigningPkHash = f.userSigningPkHash
	assignment.PublicInputHash = f.publicInputHash
	return assignment
}

func (f *mergeWitnessFixture) ringCircuit() *merge.RingCircuit {
	assignment := merge.NewMergeRingCircuit(len(f.inputs))
	assignment.Inputs = f.inputs
	assignment.Output = f.output
	assignment.MintChunks = f.mintChunkVariables()
	assignment.OwnerPkHash = f.ownerPkHash
	assignment.UserNullifierPk = f.userNullifierPk
	assignment.UserNullifierSecret = f.userNullifierSecret
	assignment.CommonPublicInputs = f.public
	assignment.OutputRingDataHash = f.outputRingDataHash
	assignment.RingProgramID = f.ringProgramID
	assignment.MemberRegistryRoot = f.memberRegistryRoot
	assignment.RegisteredCiphertextHash = f.registeredCtHash
	assignment.MemberRecord = f.memberRecord
	assignment.PublicInputHash = f.publicInputHash
	return assignment
}

func hashChain4(t testing.TB, in []*big.Int) *big.Int {
	t.Helper()
	h, err := protocol.HashChain4(in)
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
