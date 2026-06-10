//go:build spp_e2e_fixtures

package spp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"light/light-prover/prover/spp/internal/p256key"
	"light/light-prover/prover/spp/protocol"
)

// scenarioBuilder holds the owner material and sample UTXOs shared by the
// scenarios.
type scenarioBuilder struct {
	options      E2EFixtureOptions
	splAsset     *big.Int
	solAsset     *big.Int
	signerHash   *big.Int
	solanaOwner  *big.Int
	p256Owner    *big.Int
	p256Priv     *ecdsa.PrivateKey
	p256Pubkey   []byte
	utxoA, utxoB protocol.Utxo
	utxoC, solU  protocol.Utxo
	p256A, p256B protocol.Utxo
	hashA, hashB *big.Int
	hashC, solH  *big.Int
	p256HashA    *big.Int
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
			state:        map[uint64]*big.Int{},
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
			state:        map[uint64]*big.Int{},
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
			state:        map[uint64]*big.Int{},
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
			name:         fmt.Sprintf("%s_seed_%d", name, i),
			senderTag:    senderTag + 1 + int64(i),
			outputs:      []protocol.Utxo{u},
			mode:         modeShield,
			publicSpl:    uint64(amt),
			encrypted:    []byte{0xac, byte(base), byte(i)},
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
