//go:build spp_e2e_fixtures

package spp

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"light/light-prover/prover/common"
	"light/light-prover/prover/spp/protocol"
	txprover "light/light-prover/prover/spp/prover/transaction"
)

// fixtureShape is the canonical shape for the default scenarios and seed
// shields, all of which use at most 1 real input and 2 real outputs (unused
// slots are dummy-padded). The per-shape flows (transfer_2_2 .. transfer_1_8)
// prove with their own exact-arity shapes via shapeFlow.
var fixtureShape = protocol.Shape{NInputs: 1, NOutputs: 2}

const (
	fixtureExpiryUnixTs = uint64(1_000_000_000)
	fixtureTransact     = uint8(0) // tag::TRANSACT
	fixtureWrongTag     = uint8(4)

	modeTransfer = uint8(0)
	modeShield   = uint8(1)
	modeUnshield = uint8(2)

	solanaNullifierSecret = int64(99)
	p256NullifierSecret   = int64(199)
)

type E2EFixtureOptions struct {
	SolanaSignerPubkey   [32]byte
	PublicSplAssetPubkey [32]byte
	UserSolAccount       [32]byte
	UserSplToken         [32]byte
	SplTokenInterface    [32]byte
}

type E2EFixtureSet struct {
	Shape                 protocol.Shape          `json:"shape"`
	SolanaSignerPubkeyHex string                  `json:"solana_signer_pubkey"`
	ProoflessShield       *ProoflessShieldFixture `json:"proofless_shield"`
	Fixtures              []E2EFixture            `json:"fixtures"`
}

// ProoflessShieldFixture exposes the `transfer` fixture's input UTXO (as the
// owner-hiding owner_utxo_hash + public fields) so a proofless shield can create
// that exact UTXO on-chain and the `transfer` fixture can then spend it —
// proving the program's proofless UTXO hash matches the circuit's. The asset is
// the public SPL mint.
type ProoflessShieldFixture struct {
	OwnerUtxoHash string `json:"owner_utxo_hash"`
	DataHash      string `json:"data_hash"`
	ZoneDataHash  string `json:"zone_data_hash"`
	ZoneProgramID string `json:"zone_program_id"`
	Amount        uint64 `json:"amount"`
}

type E2EFixture struct {
	Name                    string         `json:"name"`
	Shape                   protocol.Shape `json:"shape"`
	RequiresP256            bool           `json:"requires_p256"`
	ExpiryUnixTs            uint64         `json:"expiry_unix_ts"`
	SenderViewTag           string         `json:"sender_view_tag"`
	Proof                   *common.Proof  `json:"proof"`
	RelayerFee              uint16         `json:"relayer_fee"`
	Nullifiers              []string       `json:"nullifiers"`
	OutputUtxoHashes        []string       `json:"output_utxo_hashes"`
	UtxoTreeRootIndex       []uint16       `json:"utxo_tree_root_index"`
	NullifierTreeRootIndex  []uint16       `json:"nullifier_tree_root_index"`
	PrivateTxHash           string         `json:"private_tx_hash"`
	PublicAmountMode        uint8          `json:"public_amount_mode"`
	PublicSolAmount         *uint64        `json:"public_sol_amount"`
	PublicSplAmount         *uint64        `json:"public_spl_amount"`
	PublicSplAssetPubkey    string         `json:"public_spl_asset_pubkey"`
	EncryptedUtxos          string         `json:"encrypted_utxos"`
	ExpectedStateNextIndex  uint64         `json:"expected_state_next_index"`
	ExpectedQueueNextIndex  uint64         `json:"expected_queue_next_index"`
	ExpectedStateRoot       string         `json:"expected_state_root"`
	PublicInputHash         string         `json:"public_input_hash"`
	ExternalDataHash        string         `json:"external_data_hash"`
	UserSolAccount          string         `json:"user_sol_account"`
	UserSplTokenAccount     string         `json:"user_spl_token_account"`
	SplTokenInterface       string         `json:"spl_token_interface"`
	SolanaOwnerInputIndices []int          `json:"solana_owner_input_indices"`
	DebugInputUtxoHashes    []string       `json:"debug_input_utxo_hashes"`
	DebugOutputUtxoHashes   []string       `json:"debug_output_utxo_hashes"`
	DebugUtxoTreeRoots      []string       `json:"debug_utxo_tree_roots"`
	DebugNullifierTreeRoots []string       `json:"debug_nullifier_tree_roots"`
}

// scenario is one transaction in the e2e sequence, expressed in protocol terms.
// It is converted to a txprover.ProofTransactionRequest and proven through the
// shared high-level prover so the transcript exactly matches production proofs.
type scenario struct {
	name      string
	tag       uint8
	senderTag int64
	inputs    []scenarioInput
	outputs   []protocol.Utxo
	mode      uint8
	publicSol uint64
	publicSpl uint64
	encrypted []byte
	state     map[uint64]*big.Int
	rootIndex uint16
	p256      bool
	shape     protocol.Shape

	expStateNext uint64
	expQueueNext uint64
	expState     map[uint64]*big.Int
}

type scenarioInput struct {
	utxo      protocol.Utxo
	leafIndex uint64
}

func WriteE2EFixturesFromKeysFile(keysFile string, path string, options E2EFixtureOptions) error {
	// Sibling spp_<N>_<M>.key files (from the same setup that produced the
	// embedded vkeys) are loaded per shape from the keys file's directory.
	set, err := BuildE2EFixtures(filepath.Dir(keysFile), options)
	if err != nil {
		return err
	}
	bytes, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	bytes = append(bytes, '\n')
	return os.WriteFile(path, bytes, 0644)
}

// proofSystemCache lazily loads one proving system per (shape, rail) from
// keyDir: spp_<N>_<M>.key for the P256-capable circuit and
// spp_<N>_<M>_solana.key for the Solana-only variant. The embedded verifying
// keys are exported from the same keys, so the fixture proofs verify.
type railKey struct {
	shape        protocol.Shape
	requiresP256 bool
}

type proofSystemCache struct {
	keyDir  string
	systems map[railKey]*txprover.ProofSystem
}

func newProofSystemCache(keyDir string) *proofSystemCache {
	return &proofSystemCache{keyDir: keyDir, systems: map[railKey]*txprover.ProofSystem{}}
}

func (c *proofSystemCache) forShapeRail(shape protocol.Shape, requiresP256 bool) (*txprover.ProofSystem, error) {
	key := railKey{shape: shape, requiresP256: requiresP256}
	if ps, ok := c.systems[key]; ok {
		return ps, nil
	}
	name := fmt.Sprintf("spp_%d_%d.key", shape.NInputs, shape.NOutputs)
	if !requiresP256 {
		name = fmt.Sprintf("spp_%d_%d_solana.key", shape.NInputs, shape.NOutputs)
	}
	path := filepath.Join(c.keyDir, name)
	ps, err := txprover.ReadProofSystem(path)
	if err != nil {
		return nil, fmt.Errorf("spp: load proving system %s: %w", path, err)
	}
	if ps.Shape != shape {
		return nil, fmt.Errorf("spp: key %s has shape %s, want %s", path, ps.Shape, shape)
	}
	// The rail is serialized in the key header; the file must match the rail we
	// loaded it for (the rail-specific filename).
	if ps.RequiresP256 != requiresP256 {
		return nil, fmt.Errorf("spp: key %s has requiresP256=%v, want %v", path, ps.RequiresP256, requiresP256)
	}
	c.systems[key] = ps
	return ps, nil
}

func BuildE2EFixtures(keyDir string, options E2EFixtureOptions) (*E2EFixtureSet, error) {
	if options.SolanaSignerPubkey == [32]byte{} {
		return nil, fmt.Errorf("spp: e2e fixtures require a Solana signer pubkey")
	}
	if options.PublicSplAssetPubkey == [32]byte{} {
		return nil, fmt.Errorf("spp: e2e fixtures require a non-zero public SPL asset pubkey")
	}

	build, err := newScenarioBuilder(options)
	if err != nil {
		return nil, err
	}
	cache := newProofSystemCache(keyDir)

	ownerUtxoHash, err := protocol.OwnerUtxoHash(build.utxoA.Owner, build.utxoA.Blinding)
	if err != nil {
		return nil, err
	}

	signerHex := bytesHex(options.SolanaSignerPubkey[:])
	set := &E2EFixtureSet{
		Shape:                 fixtureShape,
		SolanaSignerPubkeyHex: signerHex,
		ProoflessShield: &ProoflessShieldFixture{
			OwnerUtxoHash: fieldHex(ownerUtxoHash),
			DataHash:      fieldHex(build.utxoA.DataHash),
			ZoneDataHash:  fieldHex(build.utxoA.ZoneDataHash),
			ZoneProgramID: fieldHex(build.utxoA.ZoneProgramID),
			Amount:        build.utxoA.AssetAmount.Uint64(),
		},
	}
	for _, sc := range build.scenarios() {
		// A transaction uses the P256 rail only when it has a P256-owned input;
		// shields (no inputs) and Solana-owned spends use the cheaper Solana
		// rail. Matches TransactionRequiresP256 on the built request.
		requiresP256 := sc.p256 && len(sc.inputs) > 0
		ps, err := cache.forShapeRail(sc.shape, requiresP256)
		if err != nil {
			return nil, fmt.Errorf("fixture %s: %w", sc.name, err)
		}
		fixture, err := build.fixture(ps, signerHex, sc)
		if err != nil {
			return nil, fmt.Errorf("fixture %s: %w", sc.name, err)
		}
		set.Fixtures = append(set.Fixtures, fixture)
	}
	return set, nil
}
