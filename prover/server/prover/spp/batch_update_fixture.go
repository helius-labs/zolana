//go:build spp_e2e_fixtures

package spp

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"light/light-prover/prover/common"
	"light/light-prover/prover/spp/protocol"
	v2 "light/light-prover/prover/v2"
)

const (
	// The on-chain nullifier tree is a Light AddressV2 tree at height 40. Test
	// trees use batch size 10 (production uses 250; both circuits ship in
	// light-protocol). The first forester batch after init starts at tree
	// next_index 1 (the init element occupies index 0).
	batchUpdateTreeHeight = 40
	batchUpdateBatchSize  = 10
	batchUpdateStartIndex = 1
)

// BatchUpdateFixture is the input + baked Light address-append proof for the
// forester batch-update e2e. Rather than synthetically seeding the queue, the
// e2e submits Transacts (real proofs) in order; each transact queues
// [nullifiers..., view_tag] into the nullifier tree's input queue exactly like
// production. After they are submitted the queue holds Values (the first
// batchUpdateBatchSize entries, in order), the forester submits Proof via
// batch_update_address_tree, and root_history advances from OldRoot to NewRoot.
type BatchUpdateFixture struct {
	Height    uint32        `json:"height"`
	Transacts []E2EFixture  `json:"transacts"`
	Values    []string      `json:"values"`
	OldRoot   string        `json:"old_root"`
	NewRoot   string        `json:"new_root"`
	Proof     *common.Proof `json:"proof"`
}

// WriteBatchUpdateFixture builds the forester batch-update fixture and writes it
// as JSON. addressAppendKeyPath is the committed batch_address-append_40_10.key;
// sppKeyDir holds the Solana-rail transact proving keys (spp_<N>_<M>_solana.key)
// the seed/spend transacts prove against.
func WriteBatchUpdateFixture(addressAppendKeyPath, sppKeyDir, outputPath string, options E2EFixtureOptions) error {
	fixture, err := buildBatchUpdateFixture(addressAppendKeyPath, sppKeyDir, options)
	if err != nil {
		return err
	}
	bytes, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	bytes = append(bytes, '\n')
	return os.WriteFile(outputPath, bytes, 0o644)
}

func buildBatchUpdateFixture(addressAppendKeyPath, sppKeyDir string, options E2EFixtureOptions) (*BatchUpdateFixture, error) {
	if options.SolanaSignerPubkey == [32]byte{} {
		return nil, fmt.Errorf("spp: batch-update fixture requires a Solana signer pubkey")
	}
	build, err := newScenarioBuilder(options)
	if err != nil {
		return nil, err
	}
	cache := newProofSystemCache(sppKeyDir)
	signerHex := bytesHex(options.SolanaSignerPubkey[:])

	transacts, queue, err := build.batchSeedFlow(cache, signerHex)
	if err != nil {
		return nil, err
	}
	if len(queue) < batchUpdateBatchSize {
		return nil, fmt.Errorf("spp: batch flow queued %d values, need %d", len(queue), batchUpdateBatchSize)
	}
	values := queue[:batchUpdateBatchSize]

	params, err := v2.BuildAddressAppendParamsFromValues(batchUpdateTreeHeight, values, batchUpdateStartIndex)
	if err != nil {
		return nil, err
	}
	// The committed key file is a full BatchProofSystem dump (pk+vk+cs behind a
	// height/batch header); ReadSystemFromFile dispatches on the "address-append"
	// name and reads it raw, so the proof is built with the SAME setup the
	// on-chain verifying key came from.
	sys, err := common.ReadSystemFromFile(addressAppendKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read address-append proving system %s: %w", addressAppendKeyPath, err)
	}
	bps, ok := sys.(*common.BatchProofSystem)
	if !ok || bps.CircuitType != common.BatchAddressAppendCircuitType {
		return nil, fmt.Errorf("expected an address-append BatchProofSystem at %s", addressAppendKeyPath)
	}
	proof, err := v2.ProveBatchAddressAppend(bps, params)
	if err != nil {
		return nil, fmt.Errorf("prove address-append: %w", err)
	}

	valuesHex := make([]string, len(values))
	for i, v := range values {
		valuesHex[i] = fieldHex(v)
	}
	return &BatchUpdateFixture{
		Height:    batchUpdateTreeHeight,
		Transacts: transacts,
		Values:    valuesHex,
		OldRoot:   fieldHex(params.OldRoot),
		NewRoot:   fieldHex(params.NewRoot),
		Proof:     proof,
	}, nil
}

// batchSeedFlow builds the honest queue-seeding sequence: five Solana SOL
// shields (each a 0-in/1-out deposit that queues its view tag) followed by one
// 5-input SOL transfer (which queues five nullifiers plus its view tag). Proven
// in submission order, that queues 11 values; the caller appends the first
// batchUpdateBatchSize. Returns the transact fixtures (to submit in order) and
// the queued values in queue order.
func (b *scenarioBuilder) batchSeedFlow(cache *proofSystemCache, signerHex string) ([]E2EFixture, []*big.Int, error) {
	const base = int64(700)
	inAmts := []int64{30, 30, 30, 30, 30}
	outAmts := []int64{50, 50, 50}

	tree := map[uint64]*big.Int{}
	inputs := make([]scenarioInput, len(inAmts))
	var scenarios []scenario
	for i, amt := range inAmts {
		u := sampleUtxo(base+int64(i)*10, b.solanaOwner, b.solAsset, amt)
		seedState := copyState(tree)
		tree[uint64(i)] = mustHash(u)
		scenarios = append(scenarios, scenario{
			name:         fmt.Sprintf("batch_seed_%d", i),
			senderTag:    7001 + int64(i),
			outputs:      []protocol.Utxo{u},
			mode:         modeShield,
			publicSol:    uint64(amt),
			encrypted:    []byte{0xba, byte(i)},
			state:        seedState,
			shape:        fixtureShape,
			expStateNext: uint64(i) + 1,
			expQueueNext: uint64(i) + 1,
			expState:     copyState(tree),
		})
		inputs[i] = scenarioInput{utxo: u, leafIndex: uint64(i)}
	}

	spentState := copyState(tree)
	outputs := make([]protocol.Utxo, len(outAmts))
	for i, amt := range outAmts {
		o := sampleUtxo(base+1000+int64(i)*10, b.solanaOwner, b.solAsset, amt)
		outputs[i] = o
		tree[uint64(len(inAmts))+uint64(i)] = mustHash(o)
	}
	scenarios = append(scenarios, scenario{
		name: "batch_spend", senderTag: 7000, inputs: inputs, outputs: outputs,
		mode: modeTransfer, encrypted: []byte{0xbb},
		state: spentState, rootIndex: uint16(len(inAmts)), shape: protocol.Shape{NInputs: 5, NOutputs: 3},
		expStateNext: uint64(len(inAmts)) + uint64(len(outAmts)),
		expQueueNext: 2*uint64(len(inAmts)) + 1,
		expState:     tree,
	})

	var fixtures []E2EFixture
	var queue []*big.Int
	for _, sc := range scenarios {
		ps, err := cache.forShapeRail(sc.shape, false)
		if err != nil {
			return nil, nil, fmt.Errorf("batch fixture %s: %w", sc.name, err)
		}
		fx, err := b.fixture(ps, signerHex, sc)
		if err != nil {
			return nil, nil, fmt.Errorf("batch fixture %s: %w", sc.name, err)
		}
		// On-chain process_transact queues each non-zero nullifier then the
		// sender_view_tag; mirror that order exactly so the append proof matches
		// the live queue.
		for _, nh := range fx.Nullifiers {
			v, ok := new(big.Int).SetString(strings.TrimPrefix(nh, "0x"), 16)
			if !ok {
				return nil, nil, fmt.Errorf("batch fixture %s: bad nullifier hex %q", sc.name, nh)
			}
			queue = append(queue, v)
		}
		queue = append(queue, big.NewInt(sc.senderTag))
		fixtures = append(fixtures, fx)
	}
	return fixtures, queue, nil
}
