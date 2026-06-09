//go:build spp_e2e_fixtures

package spp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"light/light-prover/prover/common"
	"light/light-prover/prover/spp/internal/p256key"
	"light/light-prover/prover/spp/parse"
	"light/light-prover/prover/spp/protocol"
	txprover "light/light-prover/prover/spp/prover/transaction"
)

// fixtureShape is the single circuit shape every e2e fixture uses. Real inputs
// and outputs below this capacity are dummy-padded by the prover, so one shape
// covers shields (0 inputs), unshields (0 outputs), and transfers.
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
	ExpiryUnixTs            uint64         `json:"expiry_unix_ts"`
	SenderViewTag           string        `json:"sender_view_tag"`
	Proof                   *common.Proof `json:"proof"`
	RelayerFee              uint16        `json:"relayer_fee"`
	Nullifiers              []string      `json:"nullifiers"`
	OutputUtxoHashes        []string      `json:"output_utxo_hashes"`
	UtxoTreeRootIndex       []uint16      `json:"utxo_tree_root_index"`
	NullifierTreeRootIndex  []uint16      `json:"nullifier_tree_root_index"`
	PrivateTxHash           string        `json:"private_tx_hash"`
	PublicAmountMode        uint8         `json:"public_amount_mode"`
	PublicSolAmount         *uint64       `json:"public_sol_amount"`
	PublicSplAmount         *uint64       `json:"public_spl_amount"`
	PublicSplAssetPubkey    string        `json:"public_spl_asset_pubkey"`
	EncryptedUtxos          string        `json:"encrypted_utxos"`
	ExpectedStateNextIndex  uint64        `json:"expected_state_next_index"`
	ExpectedQueueNextIndex  uint64        `json:"expected_queue_next_index"`
	ExpectedStateRoot       string        `json:"expected_state_root"`
	PublicInputHash         string        `json:"public_input_hash"`
	ExternalDataHash        string        `json:"external_data_hash"`
	UserSolAccount          string        `json:"user_sol_account"`
	UserSplTokenAccount     string        `json:"user_spl_token_account"`
	SplTokenInterface       string        `json:"spl_token_interface"`
	SolanaOwnerInputIndices []int         `json:"solana_owner_input_indices"`
	DebugInputUtxoHashes    []string      `json:"debug_input_utxo_hashes"`
	DebugOutputUtxoHashes   []string      `json:"debug_output_utxo_hashes"`
	DebugUtxoTreeRoots      []string      `json:"debug_utxo_tree_roots"`
	DebugNullifierTreeRoots []string      `json:"debug_nullifier_tree_roots"`
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

// proofSystemCache lazily loads one proving system per shape from keyDir
// (spp_<N>_<M>.key). The embedded verifying keys are exported from the same
// keys, so the fixture proofs verify against them.
type proofSystemCache struct {
	keyDir  string
	systems map[protocol.Shape]*txprover.ProofSystem
}

func newProofSystemCache(keyDir string) *proofSystemCache {
	return &proofSystemCache{keyDir: keyDir, systems: map[protocol.Shape]*txprover.ProofSystem{}}
}

func (c *proofSystemCache) forShape(shape protocol.Shape) (*txprover.ProofSystem, error) {
	if ps, ok := c.systems[shape]; ok {
		return ps, nil
	}
	path := filepath.Join(c.keyDir, fmt.Sprintf("spp_%d_%d.key", shape.NInputs, shape.NOutputs))
	ps, err := txprover.ReadProofSystem(path)
	if err != nil {
		return nil, fmt.Errorf("spp: load proving system %s: %w", path, err)
	}
	if ps.Shape != shape {
		return nil, fmt.Errorf("spp: key %s has shape %s, want %s", path, ps.Shape, shape)
	}
	c.systems[shape] = ps
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
		ps, err := cache.forShape(sc.shape)
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

// scenarioBuilder holds the owner material and sample UTXOs shared by the
// scenarios.
type scenarioBuilder struct {
	options       E2EFixtureOptions
	splAsset      *big.Int
	solAsset      *big.Int
	signerHash    *big.Int
	solanaOwner   *big.Int
	p256Owner     *big.Int
	p256Priv      *ecdsa.PrivateKey
	p256Pubkey    []byte
	utxoA, utxoB  protocol.Utxo
	utxoC, solU   protocol.Utxo
	p256A, p256B  protocol.Utxo
	hashA, hashB  *big.Int
	hashC, solH   *big.Int
	p256HashA     *big.Int
}

func newScenarioBuilder(options E2EFixtureOptions) (*scenarioBuilder, error) {
	b := &scenarioBuilder{options: options}
	var err error
	if b.splAsset, err = protocol.SolanaPkHash(options.PublicSplAssetPubkey); err != nil {
		return nil, err
	}
	b.solAsset = protocol.SolAsset()
	b.signerHash = protocol.Sha256BEField(options.SolanaSignerPubkey[:])

	if b.solanaOwner, err = ownerHashFor(protocol.SolanaPkHash, options.SolanaSignerPubkey, solanaNullifierSecret); err != nil {
		return nil, err
	}

	if b.p256Priv, err = p256key.PrivateKeyFromScalar(big.NewInt(11)); err != nil {
		return nil, err
	}
	b.p256Pubkey = elliptic.MarshalCompressed(elliptic.P256(), b.p256Priv.PublicKey.X, b.p256Priv.PublicKey.Y)
	p256KeyHash, err := protocol.P256OwnerKeyHash(b.p256Pubkey)
	if err != nil {
		return nil, err
	}
	p256Pk, err := protocol.NullifierPk(big.NewInt(p256NullifierSecret))
	if err != nil {
		return nil, err
	}
	if b.p256Owner, err = protocol.OwnerHash(p256KeyHash, p256Pk); err != nil {
		return nil, err
	}

	b.utxoA = sampleUtxo(10, b.solanaOwner, b.splAsset, 100)
	b.utxoB = sampleUtxo(30, b.solanaOwner, b.splAsset, 60)
	b.utxoC = sampleUtxo(50, b.solanaOwner, b.splAsset, 40)
	b.solU = sampleUtxo(70, b.solanaOwner, b.solAsset, 80)
	b.p256A = sampleUtxo(90, b.p256Owner, b.splAsset, 25)
	b.p256B = sampleUtxo(110, b.p256Owner, b.splAsset, 25)
	for _, p := range []struct {
		dst **big.Int
		u   protocol.Utxo
	}{
		{&b.hashA, b.utxoA}, {&b.hashB, b.utxoB}, {&b.hashC, b.utxoC},
		{&b.solH, b.solU}, {&b.p256HashA, b.p256A},
	} {
		h, err := protocol.UtxoHash(p.u)
		if err != nil {
			return nil, err
		}
		*p.dst = h
	}
	return b, nil
}

func (b *scenarioBuilder) scenarios() []scenario {
	stateAfterShield := map[uint64]*big.Int{0: b.hashA}
	stateAfterTransfer := map[uint64]*big.Int{0: b.hashA, 1: b.hashB, 2: b.hashC}
	solAfterShield := map[uint64]*big.Int{0: b.solH}
	p256AfterShield := map[uint64]*big.Int{0: b.p256HashA}

	scenarios := []scenario{
		{
			name: "shield", senderTag: 1001, outputs: []protocol.Utxo{b.utxoA},
			mode: modeShield, publicSpl: 100, encrypted: []byte{1, 0, 10, 11},
			state: map[uint64]*big.Int{},
			expStateNext: 1, expQueueNext: 1, expState: stateAfterShield,
		},
		{
			name: "transfer", senderTag: 1002,
			inputs:  []scenarioInput{{utxo: b.utxoA, leafIndex: 0}},
			outputs: []protocol.Utxo{b.utxoB, b.utxoC},
			mode:    modeTransfer, encrypted: []byte{2, 0, 20, 21, 22},
			state: stateAfterShield, rootIndex: 1,
			expStateNext: 3, expQueueNext: 3, expState: stateAfterTransfer,
		},
		{
			name: "unshield", senderTag: 1003,
			inputs: []scenarioInput{{utxo: b.utxoC, leafIndex: 2}},
			mode:   modeUnshield, publicSpl: 40, encrypted: []byte{3, 0, 30},
			state: stateAfterTransfer, rootIndex: 2,
			expStateNext: 3, expQueueNext: 5, expState: stateAfterTransfer,
		},
		{
			name: "double_spend", senderTag: 1004,
			inputs:  []scenarioInput{{utxo: b.utxoA, leafIndex: 0}},
			outputs: []protocol.Utxo{b.utxoB, b.utxoC},
			mode:    modeTransfer, encrypted: []byte{4, 0, 40, 41, 42},
			state: stateAfterTransfer, rootIndex: 2,
			expStateNext: 3, expQueueNext: 3, expState: stateAfterTransfer,
		},
		{
			name: "sol_shield", senderTag: 2001, outputs: []protocol.Utxo{b.solU},
			mode: modeShield, publicSol: 80, encrypted: []byte{6, 0, 60, 61},
			state: map[uint64]*big.Int{},
			expStateNext: 1, expQueueNext: 1, expState: solAfterShield,
		},
		{
			name: "sol_unshield", senderTag: 2002,
			inputs: []scenarioInput{{utxo: b.solU, leafIndex: 0}},
			mode:   modeUnshield, publicSol: 80, encrypted: []byte{7, 0, 70},
			state: solAfterShield, rootIndex: 1,
			expStateNext: 1, expQueueNext: 3, expState: solAfterShield,
		},
		{
			name: "wrong_discriminator", tag: fixtureWrongTag, senderTag: 1005,
			inputs:  []scenarioInput{{utxo: b.utxoA, leafIndex: 0}},
			outputs: []protocol.Utxo{b.utxoB, b.utxoC},
			mode:    modeTransfer, encrypted: []byte{5, 0, 50, 51, 52},
			state: stateAfterShield, rootIndex: 1,
			expStateNext: 3, expQueueNext: 3, expState: stateAfterTransfer,
		},
		{
			name: "p256_shield", senderTag: 3001, outputs: []protocol.Utxo{b.p256A},
			mode: modeShield, publicSpl: 25, encrypted: []byte{8, 0, 80, 81},
			state: map[uint64]*big.Int{},
			expStateNext: 1, expQueueNext: 1, expState: p256AfterShield,
		},
		{
			name: "p256_transfer", senderTag: 3002,
			inputs:  []scenarioInput{{utxo: b.p256A, leafIndex: 0}},
			outputs: []protocol.Utxo{b.p256B},
			mode:    modeTransfer, encrypted: []byte{9, 0, 90, 91},
			state: p256AfterShield, rootIndex: 1, p256: true,
			expStateNext: 2, expQueueNext: 3, expState: map[uint64]*big.Int{0: b.p256HashA, 1: mustHash(b.p256B)},
		},
	}
	// The nine scenarios above all use the 1-2 shape (dummy-padded).
	for i := range scenarios {
		scenarios[i].shape = fixtureShape
	}

	// One self-contained SPL transfer per remaining supported shape, so every
	// embedded verifying key is exercised on-chain by a proof for its own
	// circuit. Each flow seeds its inputs with single-asset shields, then spends
	// them, so it transacts against the live program end-to-end.
	for _, flow := range [][]scenario{
		b.shapeFlow("transfer_2_2", protocol.Shape{NInputs: 2, NOutputs: 2}, 200, 4001,
			[]int64{60, 40}, []int64{70, 30}),
		b.shapeFlow("transfer_3_3", protocol.Shape{NInputs: 3, NOutputs: 3}, 300, 4101,
			[]int64{40, 40, 40}, []int64{50, 40, 30}),
		b.shapeFlow("transfer_5_3", protocol.Shape{NInputs: 5, NOutputs: 3}, 400, 5101,
			[]int64{30, 30, 30, 30, 30}, []int64{50, 50, 50}),
		b.shapeFlow("transfer_1_8", protocol.Shape{NInputs: 1, NOutputs: 8}, 500, 6101,
			[]int64{80}, []int64{10, 10, 10, 10, 10, 10, 10, 10}),
	} {
		scenarios = append(scenarios, flow...)
	}
	return scenarios
}

// shapeFlow builds an on-chain-submittable SPL transfer for one shape: each
// input UTXO is first created by a single-asset shield (`<name>_seed_<i>`, a
// 0-in/1-out deposit), then the transfer (`<name>`) spends all of them. The
// transfer references the state root after the N seed appends (root index N).
// Returns the seed fixtures followed by the transfer.
func (b *scenarioBuilder) shapeFlow(name string, shape protocol.Shape, base, senderTag int64, inAmts, outAmts []int64) []scenario {
	var flow []scenario
	inputs := make([]scenarioInput, len(inAmts))
	tree := map[uint64]*big.Int{}
	for i, amt := range inAmts {
		u := sampleUtxo(base+int64(i)*10, b.solanaOwner, b.splAsset, amt)
		seedState := copyState(tree)
		tree[uint64(i)] = mustHash(u)
		flow = append(flow, scenario{
			name:      fmt.Sprintf("%s_seed_%d", name, i),
			senderTag: senderTag + 1 + int64(i),
			outputs:   []protocol.Utxo{u},
			mode:      modeShield,
			publicSpl: uint64(amt),
			encrypted: []byte{0xac, byte(base), byte(i)},
			state:     seedState,
			shape:     fixtureShape,
			expStateNext: uint64(i) + 1,
			expQueueNext: uint64(i) + 1,
			expState:     copyState(tree),
		})
		inputs[i] = scenarioInput{utxo: u, leafIndex: uint64(i)}
	}

	spentState := copyState(tree)
	outputs := make([]protocol.Utxo, len(outAmts))
	for i, amt := range outAmts {
		o := sampleUtxo(base+1000+int64(i)*10, b.solanaOwner, b.splAsset, amt)
		outputs[i] = o
		tree[uint64(len(inAmts))+uint64(i)] = mustHash(o)
	}
	flow = append(flow, scenario{
		name: name, senderTag: senderTag, inputs: inputs, outputs: outputs,
		mode: modeTransfer, encrypted: []byte{0xab, byte(base)},
		state: spentState, rootIndex: uint16(len(inAmts)), shape: shape,
		expStateNext: uint64(len(inAmts)) + uint64(len(outAmts)),
		expQueueNext: 2*uint64(len(inAmts)) + 1,
		expState:     tree,
	})
	return flow
}

func copyState(state map[uint64]*big.Int) map[uint64]*big.Int {
	out := make(map[uint64]*big.Int, len(state))
	for k, v := range state {
		out[k] = v
	}
	return out
}

func (b *scenarioBuilder) fixture(ps *txprover.ProofSystem, signerHex string, sc scenario) (E2EFixture, error) {
	req, err := b.request(sc)
	if err != nil {
		return E2EFixture{}, err
	}

	// P256 inputs sign the proof's p256 message digest, which is only known
	// after the transcript is built, so derive it first then re-prove with the
	// signature attached.
	if sc.p256 && len(sc.inputs) > 0 {
		payload, err := txprover.BuildProofSigningPayload(ps, txprover.ProofBundleRequest{
			SolanaSignerPubkey: signerHex,
			Transactions:       []txprover.ProofTransactionRequest{req},
		})
		if err != nil {
			return E2EFixture{}, err
		}
		msg, err := parse.Hex32(payload.Transactions[0].P256MessageHash)
		if err != nil {
			return E2EFixture{}, err
		}
		r, s, err := ecdsa.Sign(rand.Reader, b.p256Priv, msg[:])
		if err != nil {
			return E2EFixture{}, err
		}
		req.P256OwnerPubkey = bytesHex(b.p256Pubkey)
		req.P256SignatureR = proofField(r)
		req.P256SignatureS = proofField(s)
	}

	bundle, err := txprover.BuildProofBundle(ps, txprover.ProofBundleRequest{
		SolanaSignerPubkey: signerHex,
		Transactions:       []txprover.ProofTransactionRequest{req},
	})
	if err != nil {
		return E2EFixture{}, err
	}
	tx := bundle.Transactions[0]

	expRoot, _, err := protocol.BuildSparseStateTree(sc.expState)
	if err != nil {
		return E2EFixture{}, err
	}

	// BuildProofBundle pads transcript arrays to the shape; the fixture (and the
	// on-chain instruction) carry only real entries and the verifier pads them
	// back to the shape with zeros. Real slots come first, so slice to the real
	// counts. Root indices are already real-length.
	nReal, mReal := len(sc.inputs), len(sc.outputs)

	return E2EFixture{
		Name:                    tx.Name,
		Shape:                   sc.shape,
		ExpiryUnixTs:            tx.ExpiryUnixTs,
		SenderViewTag:           tx.SenderViewTag,
		Proof:                   tx.Proof,
		RelayerFee:              tx.RelayerFee,
		Nullifiers:              tx.Nullifiers[:nReal],
		OutputUtxoHashes:        tx.OutputUtxoHashes[:mReal],
		UtxoTreeRootIndex:       tx.UtxoTreeRootIndex,
		NullifierTreeRootIndex:  tx.NullifierTreeRootIndex,
		PrivateTxHash:           tx.PrivateTxHash,
		PublicAmountMode:        tx.PublicAmountMode,
		PublicSolAmount:         tx.PublicSolAmount,
		PublicSplAmount:         tx.PublicSplAmount,
		PublicSplAssetPubkey:    tx.PublicSplAssetPubkey,
		EncryptedUtxos:          tx.EncryptedUtxos,
		ExpectedStateNextIndex:  sc.expStateNext,
		ExpectedQueueNextIndex:  sc.expQueueNext,
		ExpectedStateRoot:       fieldHex(expRoot),
		PublicInputHash:         tx.PublicInputHash,
		ExternalDataHash:        tx.ExternalDataHash,
		UserSolAccount:          tx.UserSolAccount,
		UserSplTokenAccount:     tx.UserSplTokenAccount,
		SplTokenInterface:       tx.SplTokenInterface,
		SolanaOwnerInputIndices: tx.SolanaOwnerInputIndices,
		DebugInputUtxoHashes:    tx.DebugInputUtxoHashes[:nReal],
		DebugOutputUtxoHashes:   tx.DebugOutputUtxoHashes[:mReal],
		DebugUtxoTreeRoots:      tx.DebugUtxoTreeRoots[:nReal],
		DebugNullifierTreeRoots: tx.DebugNullifierTreeRoots[:nReal],
	}, nil
}

// request converts a scenario into the high-level prover request.
func (b *scenarioBuilder) request(sc scenario) (txprover.ProofTransactionRequest, error) {
	tag := sc.tag
	if tag == 0 && sc.name != "" {
		tag = fixtureTransact
	}

	userSol, userSpl, splIface := b.settlementAccounts(sc)
	req := txprover.ProofTransactionRequest{
		Name:                     sc.name,
		InstructionDiscriminator: tag,
		ExpiryUnixTs:             fixtureExpiryUnixTs,
		SenderViewTag:            proofField(big.NewInt(sc.senderTag)),
		PublicAmountMode:         sc.mode,
		EncryptedUtxos:           bytesHex(sc.encrypted),
		ProgramIDHashchain:       proofField(big.NewInt(0)),
		DataHash:                 proofField(big.NewInt(0)),
		ZoneDataHash:             proofField(big.NewInt(0)),
		UserSolAccount:           bytesHex(userSol[:]),
		UserSplTokenAccount:      bytesHex(userSpl[:]),
		SplTokenInterface:        bytesHex(splIface[:]),
	}
	if sc.publicSol != 0 {
		v := sc.publicSol
		req.PublicSolAmount = &v
	}
	if sc.publicSpl != 0 {
		v := sc.publicSpl
		req.PublicSplAmount = &v
		req.PublicSplAssetPubkey = bytesHex(b.options.PublicSplAssetPubkey[:])
	}

	for index, hash := range sc.state {
		req.StateEntries = append(req.StateEntries, txprover.ProofStateEntry{
			Index: index,
			Hash:  proofField(hash),
		})
	}

	nullifierSecret := big.NewInt(solanaNullifierSecret)
	if sc.p256 {
		nullifierSecret = big.NewInt(p256NullifierSecret)
	}
	for _, in := range sc.inputs {
		utxo := b.utxoRequest(in.utxo)
		if sc.p256 {
			utxo.OwnerP256Pubkey = bytesHex(b.p256Pubkey)
		} else {
			utxo.OwnerSolanaPubkey = bytesHex(b.options.SolanaSignerPubkey[:])
		}
		utxo.Owner = ""
		req.Inputs = append(req.Inputs, txprover.ProofInputRequest{
			Utxo:            utxo,
			LeafIndex:       in.leafIndex,
			NullifierSecret: proofField(nullifierSecret),
		})
		req.UtxoTreeRootIndex = append(req.UtxoTreeRootIndex, sc.rootIndex)
		req.NullifierTreeRootIndex = append(req.NullifierTreeRootIndex, 0)
	}
	for _, out := range sc.outputs {
		req.Outputs = append(req.Outputs, b.utxoRequest(out))
	}
	return req, nil
}

func (b *scenarioBuilder) settlementAccounts(sc scenario) ([32]byte, [32]byte, [32]byte) {
	var zero [32]byte
	switch {
	case sc.publicSol != 0:
		userSol := b.options.UserSolAccount
		if userSol == zero {
			userSol = b.options.SolanaSignerPubkey
		}
		return userSol, zero, zero
	case sc.publicSpl != 0:
		return zero, b.options.UserSplToken, b.options.SplTokenInterface
	default:
		return zero, zero, zero
	}
}

// utxoRequest builds a request UTXO with its owner pinned as a raw hash (used
// directly for outputs; overwritten with owner components for inputs).
func (b *scenarioBuilder) utxoRequest(u protocol.Utxo) txprover.ProofUtxoRequest {
	return txprover.ProofUtxoRequest{
		Domain:        proofField(u.Domain),
		Owner:         proofField(u.Owner),
		AssetID:       proofField(u.AssetID),
		AssetAmount:   proofField(u.AssetAmount),
		Blinding:      proofField(u.Blinding),
		DataHash:      proofField(u.DataHash),
		ZoneDataHash:  proofField(u.ZoneDataHash),
		ZoneProgramID: proofField(u.ZoneProgramID),
	}
}

func ownerHashFor(keyHashFn func([32]byte) (*big.Int, error), pubkey [32]byte, nullifierSecret int64) (*big.Int, error) {
	keyHash, err := keyHashFn(pubkey)
	if err != nil {
		return nil, err
	}
	pk, err := protocol.NullifierPk(big.NewInt(nullifierSecret))
	if err != nil {
		return nil, err
	}
	return protocol.OwnerHash(keyHash, pk)
}

func sampleUtxo(base int64, owner, assetID *big.Int, amount int64) protocol.Utxo {
	return protocol.Utxo{
		Domain:      big.NewInt(protocol.UtxoDomain),
		Owner:       new(big.Int).Set(owner),
		AssetID:     new(big.Int).Set(assetID),
		AssetAmount: big.NewInt(amount),
		Blinding:    big.NewInt(base + 5),
		// Default transact requires bare UTXOs (no program/policy/zone data).
		DataHash:      big.NewInt(0),
		ZoneDataHash:  big.NewInt(0),
		ZoneProgramID: big.NewInt(0),
	}
}

func mustHash(u protocol.Utxo) *big.Int {
	h, err := protocol.UtxoHash(u)
	if err != nil {
		panic(err)
	}
	return h
}

func proofField(value *big.Int) string {
	return "0x" + fieldHex(value)
}

func fieldHex(value *big.Int) string {
	return fmt.Sprintf("%064x", value)
}

func bytesHex(value []byte) string {
	return fmt.Sprintf("%x", value)
}
