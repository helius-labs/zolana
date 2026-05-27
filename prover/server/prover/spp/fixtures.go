//go:build spp_e2e_fixtures

package spp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"light/light-prover/prover/common"

	"github.com/consensys/gnark/frontend"
	"golang.org/x/crypto/sha3"
)

var (
	fixtureZeroSolAccount     [32]byte
	fixtureZeroSplToken       [32]byte
	fixtureZeroTokenInterface [32]byte
)

const (
	PublicAmountNone uint8 = iota
	PublicAmountDeposit
	PublicAmountWithdraw
)

type E2EFixtureSet struct {
	Shape                 Shape        `json:"shape"`
	SolanaSignerPubkeyHex string       `json:"solana_signer_pubkey"`
	Fixtures              []E2EFixture `json:"fixtures"`
}

type E2EFixtureOptions struct {
	SolanaSignerPubkey [32]byte
	PublicSplAssetID   uint64
	UserSolAccount     [32]byte
	UserSplToken       [32]byte
	SplTokenInterface  [32]byte
}

type E2EFixture struct {
	Name                    string        `json:"name"`
	ExpiryUnixTs            uint64        `json:"expiry_unix_ts"`
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
	PublicSplAssetID        uint64        `json:"public_spl_asset_id"`
	EncryptedUtxos          string        `json:"encrypted_utxos"`
	ExpectedStateNextIndex  uint64        `json:"expected_state_next_index"`
	ExpectedQueueNextIndex  uint64        `json:"expected_queue_next_index"`
	ExpectedStateRoot       string        `json:"expected_state_root"`
	PublicInputHash         string        `json:"public_input_hash"`
	ExternalDataHash        string        `json:"external_data_hash"`
	UserSolAccount          string        `json:"user_sol_account"`
	UserSplTokenAccount     string        `json:"user_spl_token_account"`
	SplTokenInterface       string        `json:"spl_token_interface"`
	DebugInputUtxoHashes    []string      `json:"debug_input_utxo_hashes"`
	DebugOutputUtxoHashes   []string      `json:"debug_output_utxo_hashes"`
	DebugUtxoTreeRoots      []string      `json:"debug_utxo_tree_roots"`
	DebugNullifierTreeRoots []string      `json:"debug_nullifier_tree_roots"`
}

type fixtureTx struct {
	name           string
	senderTag      *big.Int
	inputs         []fixtureInput
	outputs        []Utxo
	amountMode     uint8
	publicSplDelta int64
	encryptedUtxos []byte
	stateEntries   map[uint64]*big.Int
}

type fixtureInput struct {
	utxo      Utxo
	leafIndex uint64
}

func WriteE2EFixtures(ps *ProofSystem, path string, options E2EFixtureOptions) error {
	fixtures, err := BuildE2EFixtures(ps, options)
	if err != nil {
		return err
	}
	bytes, err := json.MarshalIndent(fixtures, "", "  ")
	if err != nil {
		return err
	}
	bytes = append(bytes, '\n')
	return os.WriteFile(path, bytes, 0644)
}

func BuildE2EFixtures(ps *ProofSystem, options E2EFixtureOptions) (*E2EFixtureSet, error) {
	shape := Shape{NInputs: 1, NOutputs: 2}
	if ps.Shape != shape {
		return nil, fmt.Errorf("spp: e2e fixtures require shape %s, got %s", shape, ps.Shape)
	}
	if options.SolanaSignerPubkey == [32]byte{} {
		return nil, fmt.Errorf("spp: e2e fixtures require a Solana signer pubkey")
	}
	if options.PublicSplAssetID == 0 {
		return nil, fmt.Errorf("spp: e2e fixtures require a non-zero public SPL asset id")
	}
	if options.UserSplToken == [32]byte{} {
		return nil, fmt.Errorf("spp: e2e fixtures require a user SPL token account pubkey")
	}
	if options.SplTokenInterface == [32]byte{} {
		return nil, fmt.Errorf("spp: e2e fixtures require an SPL vault/interface pubkey")
	}

	assetID := new(big.Int).SetUint64(options.PublicSplAssetID)
	ownerHash := HashToFieldSize(options.SolanaSignerPubkey[:])
	utxoA := sampleFixtureUtxo(10, ownerHash, assetID, big.NewInt(100))
	utxoB := sampleFixtureUtxo(30, ownerHash, assetID, big.NewInt(60))
	utxoC := sampleFixtureUtxo(50, ownerHash, assetID, big.NewInt(40))

	hashA, err := UtxoHash(utxoA)
	if err != nil {
		return nil, err
	}
	hashB, err := UtxoHash(utxoB)
	if err != nil {
		return nil, err
	}
	hashC, err := UtxoHash(utxoC)
	if err != nil {
		return nil, err
	}

	stateAfterShield := map[uint64]*big.Int{0: hashA}
	stateAfterTransfer := map[uint64]*big.Int{0: hashA, 1: hashB, 2: hashC}

	txs := []fixtureTx{
		{
			name:           "shield",
			senderTag:      big.NewInt(1001),
			outputs:        []Utxo{utxoA},
			amountMode:     PublicAmountDeposit,
			publicSplDelta: 100,
			encryptedUtxos: []byte{1, 0, 10, 11},
			stateEntries:   map[uint64]*big.Int{},
		},
		{
			name:      "transfer",
			senderTag: big.NewInt(1002),
			inputs: []fixtureInput{
				{utxo: utxoA, leafIndex: 0},
			},
			outputs:        []Utxo{utxoB, utxoC},
			amountMode:     PublicAmountNone,
			publicSplDelta: 0,
			encryptedUtxos: []byte{2, 0, 20, 21, 22},
			stateEntries:   stateAfterShield,
		},
		{
			name:      "unshield",
			senderTag: big.NewInt(1003),
			inputs: []fixtureInput{
				{utxo: utxoC, leafIndex: 2},
			},
			outputs:        nil,
			amountMode:     PublicAmountWithdraw,
			publicSplDelta: -40,
			encryptedUtxos: []byte{3, 0, 30},
			stateEntries:   stateAfterTransfer,
		},
	}

	out := &E2EFixtureSet{
		Shape:                 shape,
		SolanaSignerPubkeyHex: bytesHex(options.SolanaSignerPubkey[:]),
	}
	stateNextIndex := uint64(0)
	queueNextIndex := uint64(0)
	for _, tx := range txs {
		fixture, err := buildE2EFixture(ps, shape, tx, assetID, ownerHash, options)
		if err != nil {
			return nil, err
		}
		stateNextIndex += uint64(len(tx.outputs))
		queueNextIndex += uint64(len(tx.inputs)) + 1
		root, _ := BuildSparseStateTree(nextStateEntries(tx.name, hashA, hashB, hashC))
		fixture.ExpectedStateNextIndex = stateNextIndex
		fixture.ExpectedQueueNextIndex = queueNextIndex
		fixture.ExpectedStateRoot = fieldHex(root)
		out.Fixtures = append(out.Fixtures, fixture)
	}

	doubleSpend := fixtureTx{
		name:      "double_spend",
		senderTag: big.NewInt(1004),
		inputs: []fixtureInput{
			{utxo: utxoA, leafIndex: 0},
		},
		outputs:        []Utxo{utxoB, utxoC},
		amountMode:     PublicAmountNone,
		publicSplDelta: 0,
		encryptedUtxos: []byte{4, 0, 40, 41, 42},
		stateEntries:   stateAfterTransfer,
	}
	fixture, err := buildE2EFixture(ps, shape, doubleSpend, assetID, ownerHash, options)
	if err != nil {
		return nil, err
	}
	root, _ := BuildSparseStateTree(stateAfterTransfer)
	fixture.ExpectedStateNextIndex = 3
	fixture.ExpectedQueueNextIndex = 3
	fixture.ExpectedStateRoot = fieldHex(root)
	out.Fixtures = append(out.Fixtures, fixture)
	return out, nil
}

func buildE2EFixture(ps *ProofSystem, shape Shape, tx fixtureTx, assetID, signerHash *big.Int, options E2EFixtureOptions) (E2EFixture, error) {
	assignment, publicInputs, debug, err := buildFixtureAssignment(shape, tx, assetID, signerHash, options)
	if err != nil {
		return E2EFixture{}, err
	}
	proof, err := Prove(ps, assignment)
	if err != nil {
		return E2EFixture{}, err
	}
	if err := Verify(ps, assignment, proof); err != nil {
		return E2EFixture{}, err
	}

	publicInputHash, err := PublicInputHash(publicInputs)
	if err != nil {
		return E2EFixture{}, err
	}

	publicSplAmount := uint64(abs64(tx.publicSplDelta))
	userSolAccount, userSplTokenAccount, splTokenInterface := fixtureSettlementAccounts(tx, options)
	nullifierIndices := make([]uint16, len(tx.inputs))
	outputHashes := trimTrailingZeroHexes(debug.outputHashes)
	fixture := E2EFixture{
		Name:                    tx.name,
		ExpiryUnixTs:            1_000_000_000,
		SenderViewTag:           fieldHex(tx.senderTag),
		Proof:                   &common.Proof{Proof: proof},
		RelayerFee:              0,
		Nullifiers:              trimTrailingZeroHexes(debug.nullifiers),
		OutputUtxoHashes:        outputHashes,
		UtxoTreeRootIndex:       nullifierIndices,
		NullifierTreeRootIndex:  nullifierIndices,
		PrivateTxHash:           fieldHex(publicInputs.PrivateTxHash),
		PublicAmountMode:        tx.amountMode,
		PublicSolAmount:         nil,
		PublicSplAmount:         &publicSplAmount,
		PublicSplAssetID:        assetID.Uint64(),
		EncryptedUtxos:          bytesHex(tx.encryptedUtxos),
		PublicInputHash:         fieldHex(publicInputHash),
		ExternalDataHash:        fieldHex(publicInputs.ExternalDataHash),
		UserSolAccount:          bytesHex(userSolAccount[:]),
		UserSplTokenAccount:     bytesHex(userSplTokenAccount[:]),
		SplTokenInterface:       bytesHex(splTokenInterface[:]),
		DebugInputUtxoHashes:    bigIntHexes(debug.inputHashes),
		DebugOutputUtxoHashes:   bigIntHexes(debug.outputHashes),
		DebugUtxoTreeRoots:      bigIntHexes(publicInputs.UtxoTreeRoots),
		DebugNullifierTreeRoots: bigIntHexes(publicInputs.NullifierRoots),
	}
	if tx.publicSplDelta == 0 && tx.amountMode == PublicAmountNone {
		fixture.PublicSplAmount = nil
		fixture.PublicSplAssetID = 0
	}
	return fixture, nil
}

type fixtureDebug struct {
	inputHashes  []*big.Int
	outputHashes []*big.Int
	nullifiers   []*big.Int
}

func buildFixtureAssignment(shape Shape, tx fixtureTx, assetID, signerHash *big.Int, options E2EFixtureOptions) (*Circuit, PublicInputs, fixtureDebug, error) {
	inputUtxos := make([]UtxoCircuitFields, shape.NInputs)
	preNullifiers := make([]frontend.Variable, shape.NInputs)
	isDummyInput := make([]frontend.Variable, shape.NInputs)
	statePath := make([][]frontend.Variable, shape.NInputs)
	stateDirs := make([][]frontend.Variable, shape.NInputs)
	nfLowValue := make([]frontend.Variable, shape.NInputs)
	nfNextValue := make([]frontend.Variable, shape.NInputs)
	nfLowPath := make([][]frontend.Variable, shape.NInputs)
	nfLowDirs := make([][]frontend.Variable, shape.NInputs)
	nullifiers := make([]frontend.Variable, shape.NInputs)
	inputHashes := make([]*big.Int, shape.NInputs)
	utxoRoots := make([]*big.Int, shape.NInputs)
	nullifierRoots := make([]*big.Int, shape.NInputs)

	stateRoot, stateProofs := BuildSparseStateTree(tx.stateEntries)
	nullifierTree := NewIndexedTree()
	nullifierSecret := big.NewInt(99)

	for i := 0; i < shape.NInputs; i++ {
		statePath[i] = zeroVariableSlice(StateTreeHeight)
		stateDirs[i] = zeroVariableSlice(StateTreeHeight)
		nfLowPath[i] = zeroVariableSlice(NullifierTreeHeight)
		nfLowDirs[i] = zeroVariableSlice(NullifierTreeHeight)
		nfLowValue[i] = big.NewInt(0)
		nfNextValue[i] = big.NewInt(0)
		utxoRoots[i] = big.NewInt(0)
		nullifierRoots[i] = big.NewInt(0)

		if i >= len(tx.inputs) {
			inputUtxos[i] = toFixtureCircuitFields(zeroUtxo())
			preNullifiers[i] = big.NewInt(0)
			isDummyInput[i] = frontend.Variable(1)
			nullifiers[i] = big.NewInt(0)
			inputHashes[i] = big.NewInt(0)
			continue
		}

		input := tx.inputs[i]
		inputUtxos[i] = toFixtureCircuitFields(input.utxo)
		inputHash, err := UtxoHash(input.utxo)
		if err != nil {
			return nil, PublicInputs{}, fixtureDebug{}, err
		}
		preNullifier, err := PreNullifier(input.utxo.Blinding, nullifierSecret)
		if err != nil {
			return nil, PublicInputs{}, fixtureDebug{}, err
		}
		nullifier, err := NullifierHash(inputHash, preNullifier)
		if err != nil {
			return nil, PublicInputs{}, fixtureDebug{}, err
		}
		inputHashes[i] = inputHash
		preNullifiers[i] = preNullifier
		isDummyInput[i] = frontend.Variable(0)
		nullifiers[i] = nullifier
		utxoRoots[i] = stateRoot
		nullifierRoots[i] = nullifierTree.Root

		proof, ok := stateProofs[input.leafIndex]
		if !ok {
			return nil, PublicInputs{}, fixtureDebug{}, fmt.Errorf("spp: missing state proof for leaf %d", input.leafIndex)
		}
		fillFixturePath(statePath[i], stateDirs[i], proof.Siblings, proof.Directions)

		nfWitness := nullifierTree.NonInclusion(nullifier)
		nfLowValue[i] = nfWitness.LowValue
		nfNextValue[i] = nfWitness.NextValue
		fillFixturePath(nfLowPath[i], nfLowDirs[i], nfWitness.Siblings, nfWitness.Directions)
	}

	outputUtxos := make([]UtxoCircuitFields, shape.NOutputs)
	isDummyOutput := make([]frontend.Variable, shape.NOutputs)
	outputHashes := make([]*big.Int, shape.NOutputs)
	outputHashVars := make([]frontend.Variable, shape.NOutputs)
	for i := 0; i < shape.NOutputs; i++ {
		if i >= len(tx.outputs) {
			outputUtxos[i] = toFixtureCircuitFields(zeroUtxo())
			isDummyOutput[i] = frontend.Variable(1)
			outputHashes[i] = big.NewInt(0)
			outputHashVars[i] = big.NewInt(0)
			continue
		}
		outputUtxos[i] = toFixtureCircuitFields(tx.outputs[i])
		outputHash, err := UtxoHash(tx.outputs[i])
		if err != nil {
			return nil, PublicInputs{}, fixtureDebug{}, err
		}
		isDummyOutput[i] = frontend.Variable(0)
		outputHashes[i] = outputHash
		outputHashVars[i] = outputHash
	}

	expiry := big.NewInt(1_000_000_000)
	userSolAccount, userSplTokenAccount, splTokenInterface := fixtureSettlementAccounts(tx, options)
	externalDataHash := ExternalDataFieldHash(ExternalData{
		SenderViewTag:     fieldBytes(tx.senderTag),
		RelayerFee:        0,
		PublicSolAmount:   0,
		PublicSplAmount:   uint64(abs64(tx.publicSplDelta)),
		UserSolAccount:    userSolAccount,
		UserSplToken:      userSplTokenAccount,
		SplTokenInterface: splTokenInterface,
		EncryptedUtxos:    tx.encryptedUtxos,
	})
	privateTxHash, err := PrivateTxHash(inputHashes, outputHashes, externalDataHash, expiry)
	if err != nil {
		return nil, PublicInputs{}, fixtureDebug{}, err
	}
	publicSplAmount := SignedToFe(big.NewInt(tx.publicSplDelta))
	publicSplAsset := big.NewInt(0)
	if tx.publicSplDelta != 0 {
		publicSplAsset = assetID
	}
	publicInputs := PublicInputs{
		Nullifiers:           toFixtureBigInts(nullifiers),
		OutputUtxoHashes:     outputHashes,
		UtxoTreeRoots:        utxoRoots,
		NullifierRoots:       nullifierRoots,
		PrivateTxHash:        privateTxHash,
		ExternalDataHash:     externalDataHash,
		ExpiryUnixTs:         expiry,
		PublicAmountMode:     big.NewInt(int64(tx.amountMode)),
		PublicSolAmount:      big.NewInt(0),
		PublicSplAmount:      publicSplAmount,
		RelayerFee:           big.NewInt(0),
		PublicSplAssetPubkey: publicSplAsset,
		ProgramIDHashchain:   big.NewInt(0),
		SolanaPubkeyHash:     new(big.Int).Set(signerHash),
		DataHash:             big.NewInt(0),
		PolicyData:           big.NewInt(0),
	}
	publicInputHash, err := PublicInputHash(publicInputs)
	if err != nil {
		return nil, PublicInputs{}, fixtureDebug{}, err
	}

	assignment := &Circuit{
		Shape:                shape,
		InputUtxos:           inputUtxos,
		PreNullifiers:        preNullifiers,
		IsDummyInput:         isDummyInput,
		StatePath:            statePath,
		StatePathDirs:        stateDirs,
		NfLowValue:           nfLowValue,
		NfNextValue:          nfNextValue,
		NfLowPath:            nfLowPath,
		NfLowPathDirs:        nfLowDirs,
		UtxoTreeRoots:        toFixtureVariables(utxoRoots),
		NullifierRoots:       toFixtureVariables(nullifierRoots),
		OutputUtxos:          outputUtxos,
		IsDummyOutput:        isDummyOutput,
		ExternalDataHash:     externalDataHash,
		ExpiryUnixTs:         expiry,
		PublicAmountMode:     publicInputs.PublicAmountMode,
		RelayerFee:           publicInputs.RelayerFee,
		Nullifiers:           nullifiers,
		OutputUtxoHashes:     outputHashVars,
		PrivateTxHash:        privateTxHash,
		PublicSolAmount:      publicInputs.PublicSolAmount,
		PublicSplAmount:      publicInputs.PublicSplAmount,
		PublicSplAssetPubkey: publicInputs.PublicSplAssetPubkey,
		ProgramIDHashchain:   publicInputs.ProgramIDHashchain,
		SolanaPubkeyHash:     publicInputs.SolanaPubkeyHash,
		DataHash:             publicInputs.DataHash,
		PolicyData:           publicInputs.PolicyData,
		PublicInputHash:      publicInputHash,
	}
	return assignment, publicInputs, fixtureDebug{
		inputHashes:  inputHashes,
		outputHashes: outputHashes,
		nullifiers:   toFixtureBigInts(nullifiers),
	}, nil
}

type ExternalData struct {
	SenderViewTag     [32]byte
	RelayerFee        uint16
	PublicSolAmount   uint64
	PublicSplAmount   uint64
	UserSolAccount    [32]byte
	UserSplToken      [32]byte
	SplTokenInterface [32]byte
	EncryptedUtxos    []byte
}

func ExternalDataFieldHash(data ExternalData) *big.Int {
	// TODO(v2): strengthen this encoding with explicit direction and
	// length-delimited encrypted outputs before adding richer transaction
	// variants. v1 keeps the spec's flat field order.
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data.SenderViewTag[:])
	var fee [2]byte
	binary.BigEndian.PutUint16(fee[:], data.RelayerFee)
	hasher.Write(fee[:])
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], data.PublicSolAmount)
	hasher.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], data.PublicSplAmount)
	hasher.Write(buf[:])
	hasher.Write(data.UserSolAccount[:])
	hasher.Write(data.UserSplToken[:])
	hasher.Write(data.SplTokenInterface[:])
	hasher.Write(data.EncryptedUtxos)
	hasher.Write([]byte{255})
	sum := hasher.Sum(nil)
	sum[0] = 0
	return new(big.Int).SetBytes(sum)
}

func fixtureSettlementAccounts(tx fixtureTx, options E2EFixtureOptions) ([32]byte, [32]byte, [32]byte) {
	if tx.publicSplDelta != 0 {
		return fixtureZeroSolAccount, options.UserSplToken, options.SplTokenInterface
	}
	return fixtureZeroSolAccount, fixtureZeroSplToken, fixtureZeroTokenInterface
}

func nextStateEntries(name string, hashA, hashB, hashC *big.Int) map[uint64]*big.Int {
	switch name {
	case "shield":
		return map[uint64]*big.Int{0: hashA}
	case "transfer", "unshield":
		return map[uint64]*big.Int{0: hashA, 1: hashB, 2: hashC}
	default:
		return map[uint64]*big.Int{}
	}
}

func sampleFixtureUtxo(base int64, ownerHash, assetID, amount *big.Int) Utxo {
	return Utxo{
		Domain:          big.NewInt(base + 1),
		Owner:           new(big.Int).Set(ownerHash),
		AssetID:         new(big.Int).Set(assetID),
		AssetAmount:     new(big.Int).Set(amount),
		Blinding:        big.NewInt(base + 5),
		DataHash:        big.NewInt(base + 6),
		PolicyData:      big.NewInt(base + 7),
		PolicyProgramID: big.NewInt(0),
	}
}

func zeroUtxo() Utxo {
	return Utxo{
		Domain:          big.NewInt(0),
		Owner:           big.NewInt(0),
		AssetID:         big.NewInt(0),
		AssetAmount:     big.NewInt(0),
		Blinding:        big.NewInt(0),
		DataHash:        big.NewInt(0),
		PolicyData:      big.NewInt(0),
		PolicyProgramID: big.NewInt(0),
	}
}

func toFixtureCircuitFields(utxo Utxo) UtxoCircuitFields {
	return UtxoCircuitFields{
		Domain:          utxo.Domain,
		Owner:           utxo.Owner,
		AssetID:         utxo.AssetID,
		AssetAmount:     utxo.AssetAmount,
		Blinding:        utxo.Blinding,
		DataHash:        utxo.DataHash,
		PolicyData:      utxo.PolicyData,
		PolicyProgramID: utxo.PolicyProgramID,
	}
}

func zeroVariableSlice(n int) []frontend.Variable {
	out := make([]frontend.Variable, n)
	for i := range out {
		out[i] = big.NewInt(0)
	}
	return out
}

func fillFixturePath(path []frontend.Variable, dirs []frontend.Variable, siblings []*big.Int, directions []int) {
	for i := range siblings {
		path[i] = siblings[i]
		dirs[i] = big.NewInt(int64(directions[i]))
	}
}

func toFixtureVariables(values []*big.Int) []frontend.Variable {
	out := make([]frontend.Variable, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

func toFixtureBigInts(values []frontend.Variable) []*big.Int {
	out := make([]*big.Int, len(values))
	for i, value := range values {
		switch v := value.(type) {
		case *big.Int:
			out[i] = new(big.Int).Set(v)
		case int:
			out[i] = big.NewInt(int64(v))
		case int64:
			out[i] = big.NewInt(v)
		default:
			out[i] = new(big.Int).SetInt64(0)
			fmt.Sscan(fmt.Sprint(v), out[i])
		}
	}
	return out
}

func trimTrailingZeroHexes(values []*big.Int) []string {
	end := len(values)
	for end > 0 && values[end-1].Sign() == 0 {
		end--
	}
	out := make([]string, end)
	for i := 0; i < end; i++ {
		out[i] = fieldHex(values[i])
	}
	return out
}

func bigIntHexes(values []*big.Int) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = fieldHex(value)
	}
	return out
}

func fieldHex(value *big.Int) string {
	return fmt.Sprintf("%064x", value)
}

func bytesHex(value []byte) string {
	return fmt.Sprintf("%x", value)
}

func fieldBytes(value *big.Int) [32]byte {
	var out [32]byte
	bytes := value.Bytes()
	copy(out[32-len(bytes):], bytes)
	return out
}

func abs64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}
