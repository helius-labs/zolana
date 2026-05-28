package spp

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

// Circuit is the SPP v1 circuit for one fixed (N inputs, M outputs) shape.
// TODO(v2): replace per-shape dispatch with one fixed wide circuit if the spec
// moves to a single proving key.
type Circuit struct {
	Shape Shape `gnark:"-"`

	InputUtxos       []UtxoCircuitFields
	InputNullifierPk []frontend.Variable
	IsDummyInput     []frontend.Variable
	StatePath        [][]frontend.Variable
	StatePathDirs    [][]frontend.Variable
	NfLowValue       []frontend.Variable
	NfNextValue      []frontend.Variable
	NfLowPath        [][]frontend.Variable
	NfLowPathDirs    [][]frontend.Variable
	UtxoTreeRoots    []frontend.Variable
	NullifierRoots   []frontend.Variable

	OutputUtxos   []UtxoCircuitFields
	IsDummyOutput []frontend.Variable

	ExternalDataHash frontend.Variable
	ExpiryUnixTs     frontend.Variable
	PublicAmountMode frontend.Variable
	RelayerFee       frontend.Variable
	NullifierSecret  frontend.Variable
	P256Pub          gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	P256Sig          gnarkecdsa.Signature[emulated.P256Fr]

	// Logical public inputs from spec v1. They are folded into PublicInputHash
	// so the on-chain verifier can reconstruct one BN254 field element from
	// instruction data and account state.
	Nullifiers           []frontend.Variable
	OutputUtxoHashes     []frontend.Variable
	PrivateTxHash        frontend.Variable
	PublicSolAmount      frontend.Variable
	PublicSplAmount      frontend.Variable
	PublicSplAssetPubkey frontend.Variable
	ProgramIDHashchain   frontend.Variable
	SolanaPubkeyHash     frontend.Variable
	SolanaPkHashes       []frontend.Variable
	DataHash             frontend.Variable
	PolicyData           frontend.Variable

	PublicInputHash frontend.Variable `gnark:",public"`
}

func NewCircuit(shape Shape) (*Circuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	c := &Circuit{
		Shape:            shape,
		InputUtxos:       make([]UtxoCircuitFields, shape.NInputs),
		InputNullifierPk: make([]frontend.Variable, shape.NInputs),
		IsDummyInput:     make([]frontend.Variable, shape.NInputs),
		StatePath:        make([][]frontend.Variable, shape.NInputs),
		StatePathDirs:    make([][]frontend.Variable, shape.NInputs),
		NfLowValue:       make([]frontend.Variable, shape.NInputs),
		NfNextValue:      make([]frontend.Variable, shape.NInputs),
		NfLowPath:        make([][]frontend.Variable, shape.NInputs),
		NfLowPathDirs:    make([][]frontend.Variable, shape.NInputs),
		UtxoTreeRoots:    make([]frontend.Variable, shape.NInputs),
		NullifierRoots:   make([]frontend.Variable, shape.NInputs),
		OutputUtxos:      make([]UtxoCircuitFields, shape.NOutputs),
		IsDummyOutput:    make([]frontend.Variable, shape.NOutputs),
		Nullifiers:       make([]frontend.Variable, shape.NInputs),
		OutputUtxoHashes: make([]frontend.Variable, shape.NOutputs),
		SolanaPkHashes:   make([]frontend.Variable, shape.NInputs),
	}
	for i := 0; i < shape.NInputs; i++ {
		c.StatePath[i] = make([]frontend.Variable, StateTreeHeight)
		c.StatePathDirs[i] = make([]frontend.Variable, StateTreeHeight)
		c.NfLowPath[i] = make([]frontend.Variable, NullifierTreeHeight)
		c.NfLowPathDirs[i] = make([]frontend.Variable, NullifierTreeHeight)
	}
	return c, nil
}

func MustNewCircuit(shape Shape) *Circuit {
	circuit, err := NewCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

func (c *Circuit) Define(api frontend.API) error {
	if err := c.validateShape(); err != nil {
		return err
	}

	nullifierPkFromSecret := NullifierPkCircuit(api, c.NullifierSecret)
	p256OwnerKeyHash := P256OwnerKeyHashFromPubkeyCircuit(api, c.P256Pub)
	p256Message := privateTxHashToP256Fr(api, c.PrivateTxHash)
	p256SigValid := c.P256Pub.IsValid(
		api,
		sw_emulated.GetCurveParams[emulated.P256Fp](),
		p256Message,
		&c.P256Sig,
	)
	inputHashes := make([]frontend.Variable, c.Shape.NInputs)
	for i := 0; i < c.Shape.NInputs; i++ {
		api.AssertIsBoolean(c.IsDummyInput[i])
		notDummy := api.Sub(1, c.IsDummyInput[i])
		api.AssertIsEqual(api.Mul(c.IsDummyInput[i], c.InputUtxos[i].AssetAmount), 0)

		inputHash := UtxoHashCircuit(api, c.InputUtxos[i])
		inputHashes[i] = api.Select(c.IsDummyInput[i], frontend.Variable(0), inputHash)
		stateRoot := StatePathFoldCircuit(api, inputHash, c.StatePath[i], c.StatePathDirs[i])
		api.AssertIsEqual(api.Mul(notDummy, api.Sub(stateRoot, c.UtxoTreeRoots[i])), 0)

		isP256Input := api.IsZero(c.SolanaPkHashes[i])
		ownerKeyHash := api.Select(isP256Input, p256OwnerKeyHash, c.SolanaPkHashes[i])
		ownerHash := OwnerHashCircuit(api, ownerKeyHash, c.InputNullifierPk[i])
		api.AssertIsEqual(api.Mul(notDummy, api.Sub(ownerHash, c.InputUtxos[i].Owner)), 0)
		api.AssertIsEqual(api.Mul(notDummy, api.Sub(nullifierPkFromSecret, c.InputNullifierPk[i])), 0)
		api.AssertIsEqual(api.Mul(notDummy, isP256Input, api.Sub(1, p256SigValid)), 0)
		api.AssertIsEqual(api.Mul(c.IsDummyInput[i], c.InputNullifierPk[i]), 0)
		api.AssertIsEqual(api.Mul(c.IsDummyInput[i], c.SolanaPkHashes[i]), 0)

		nullifier := NullifierHashCircuit(api, inputHash, c.InputUtxos[i].Blinding, c.NullifierSecret)
		api.AssertIsEqual(api.Mul(notDummy, api.Sub(nullifier, c.Nullifiers[i])), 0)
		api.AssertIsEqual(api.Mul(c.IsDummyInput[i], c.Nullifiers[i]), 0)

		lowLeafHash := IndexedLeafHashCircuit(api, c.NfLowValue[i], c.NfNextValue[i])
		nfRoot := StatePathFoldCircuit(api, lowLeafHash, c.NfLowPath[i], c.NfLowPathDirs[i])
		api.AssertIsEqual(api.Mul(notDummy, api.Sub(nfRoot, c.NullifierRoots[i])), 0)

		lowEff := api.Select(c.IsDummyInput[i], frontend.Variable(0), c.NfLowValue[i])
		nullifierEff := api.Select(c.IsDummyInput[i], frontend.Variable(1), c.Nullifiers[i])
		nextEff := api.Select(c.IsDummyInput[i], frontend.Variable(2), c.NfNextValue[i])
		api.AssertIsLessOrEqual(api.Add(lowEff, 1), nullifierEff)
		api.AssertIsLessOrEqual(api.Add(nullifierEff, 1), nextEff)
	}

	outputHashes := make([]frontend.Variable, c.Shape.NOutputs)
	for i := 0; i < c.Shape.NOutputs; i++ {
		api.AssertIsBoolean(c.IsDummyOutput[i])
		notDummy := api.Sub(1, c.IsDummyOutput[i])
		api.AssertIsEqual(api.Mul(c.IsDummyOutput[i], c.OutputUtxos[i].AssetAmount), 0)

		outputHash := UtxoHashCircuit(api, c.OutputUtxos[i])
		outputHashes[i] = api.Select(c.IsDummyOutput[i], frontend.Variable(0), outputHash)
		api.AssertIsEqual(api.Mul(notDummy, api.Sub(outputHash, c.OutputUtxoHashes[i])), 0)
		api.AssertIsEqual(api.Mul(c.IsDummyOutput[i], c.OutputUtxoHashes[i]), 0)
	}

	assertBalanceConservation(
		api,
		c.InputUtxos,
		c.OutputUtxos,
		c.PublicSolAmount,
		c.PublicSplAmount,
		c.PublicSplAssetPubkey,
	)

	privateTxHash := PrivateTxHashCircuit(
		api,
		inputHashes,
		outputHashes,
		c.ExternalDataHash,
		c.ExpiryUnixTs,
	)
	api.AssertIsEqual(privateTxHash, c.PrivateTxHash)

	api.AssertIsEqual(c.PublicInputHash, c.publicInputHash(api))
	return nil
}

func (c *Circuit) publicInputHash(api frontend.API) frontend.Variable {
	return HashChainCircuit(api, []frontend.Variable{
		HashChainCircuit(api, c.Nullifiers),
		HashChainCircuit(api, c.OutputUtxoHashes),
		HashChainCircuit(api, c.UtxoTreeRoots),
		HashChainCircuit(api, c.NullifierRoots),
		c.PrivateTxHash,
		c.ExternalDataHash,
		c.PublicSolAmount,
		c.PublicSplAmount,
		c.PublicSplAssetPubkey,
		c.ProgramIDHashchain,
		c.SolanaPubkeyHash,
		c.DataHash,
		c.PolicyData,
		HashChainCircuit(api, c.SolanaPkHashes),
	})
}

func (c *Circuit) validateShape() error {
	if err := c.Shape.Validate(); err != nil {
		return err
	}
	if len(c.InputUtxos) != c.Shape.NInputs {
		return fmt.Errorf("spp: input UTXO count mismatch: got %d want %d", len(c.InputUtxos), c.Shape.NInputs)
	}
	if len(c.InputNullifierPk) != c.Shape.NInputs {
		return fmt.Errorf("spp: input nullifier pk count mismatch: got %d want %d", len(c.InputNullifierPk), c.Shape.NInputs)
	}
	if len(c.IsDummyInput) != c.Shape.NInputs {
		return fmt.Errorf("spp: dummy input flag count mismatch: got %d want %d", len(c.IsDummyInput), c.Shape.NInputs)
	}
	if len(c.StatePath) != c.Shape.NInputs {
		return fmt.Errorf("spp: state path count mismatch: got %d want %d", len(c.StatePath), c.Shape.NInputs)
	}
	if len(c.StatePathDirs) != c.Shape.NInputs {
		return fmt.Errorf("spp: state path direction count mismatch: got %d want %d", len(c.StatePathDirs), c.Shape.NInputs)
	}
	if len(c.NfLowValue) != c.Shape.NInputs {
		return fmt.Errorf("spp: nullifier low value count mismatch: got %d want %d", len(c.NfLowValue), c.Shape.NInputs)
	}
	if len(c.NfNextValue) != c.Shape.NInputs {
		return fmt.Errorf("spp: nullifier next value count mismatch: got %d want %d", len(c.NfNextValue), c.Shape.NInputs)
	}
	if len(c.NfLowPath) != c.Shape.NInputs {
		return fmt.Errorf("spp: nullifier low path count mismatch: got %d want %d", len(c.NfLowPath), c.Shape.NInputs)
	}
	if len(c.NfLowPathDirs) != c.Shape.NInputs {
		return fmt.Errorf("spp: nullifier low path direction count mismatch: got %d want %d", len(c.NfLowPathDirs), c.Shape.NInputs)
	}
	if len(c.UtxoTreeRoots) != c.Shape.NInputs {
		return fmt.Errorf("spp: UTXO tree root count mismatch: got %d want %d", len(c.UtxoTreeRoots), c.Shape.NInputs)
	}
	if len(c.NullifierRoots) != c.Shape.NInputs {
		return fmt.Errorf("spp: nullifier tree root count mismatch: got %d want %d", len(c.NullifierRoots), c.Shape.NInputs)
	}
	for i := 0; i < c.Shape.NInputs; i++ {
		if len(c.StatePath[i]) != StateTreeHeight {
			return fmt.Errorf("spp: state path %d height mismatch: got %d want %d", i, len(c.StatePath[i]), StateTreeHeight)
		}
		if len(c.StatePathDirs[i]) != StateTreeHeight {
			return fmt.Errorf("spp: state path direction %d height mismatch: got %d want %d", i, len(c.StatePathDirs[i]), StateTreeHeight)
		}
		if len(c.NfLowPath[i]) != NullifierTreeHeight {
			return fmt.Errorf("spp: nullifier low path %d height mismatch: got %d want %d", i, len(c.NfLowPath[i]), NullifierTreeHeight)
		}
		if len(c.NfLowPathDirs[i]) != NullifierTreeHeight {
			return fmt.Errorf("spp: nullifier low path direction %d height mismatch: got %d want %d", i, len(c.NfLowPathDirs[i]), NullifierTreeHeight)
		}
	}
	if len(c.OutputUtxos) != c.Shape.NOutputs {
		return fmt.Errorf("spp: output UTXO count mismatch: got %d want %d", len(c.OutputUtxos), c.Shape.NOutputs)
	}
	if len(c.IsDummyOutput) != c.Shape.NOutputs {
		return fmt.Errorf("spp: dummy output flag count mismatch: got %d want %d", len(c.IsDummyOutput), c.Shape.NOutputs)
	}
	if len(c.Nullifiers) != c.Shape.NInputs {
		return fmt.Errorf("spp: nullifier count mismatch: got %d want %d", len(c.Nullifiers), c.Shape.NInputs)
	}
	if len(c.OutputUtxoHashes) != c.Shape.NOutputs {
		return fmt.Errorf("spp: output UTXO hash count mismatch: got %d want %d", len(c.OutputUtxoHashes), c.Shape.NOutputs)
	}
	if len(c.SolanaPkHashes) != c.Shape.NInputs {
		return fmt.Errorf("spp: solana pk hash count mismatch: got %d want %d", len(c.SolanaPkHashes), c.Shape.NInputs)
	}
	return nil
}

type PublicInputs struct {
	Nullifiers           []*big.Int
	OutputUtxoHashes     []*big.Int
	UtxoTreeRoots        []*big.Int
	NullifierRoots       []*big.Int
	PrivateTxHash        *big.Int
	ExternalDataHash     *big.Int
	ExpiryUnixTs         *big.Int
	PublicAmountMode     *big.Int
	PublicSolAmount      *big.Int
	PublicSplAmount      *big.Int
	RelayerFee           *big.Int
	PublicSplAssetPubkey *big.Int
	ProgramIDHashchain   *big.Int
	SolanaPubkeyHash     *big.Int
	SolanaPkHashes       []*big.Int
	DataHash             *big.Int
	PolicyData           *big.Int
}

func PublicInputHash(inputs PublicInputs) (*big.Int, error) {
	nullifierChain, err := HashChain(inputs.Nullifiers)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash nullifier chain: %w", err)
	}
	outputChain, err := HashChain(inputs.OutputUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash output chain: %w", err)
	}
	utxoRootChain, err := HashChain(inputs.UtxoTreeRoots)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash UTXO root chain: %w", err)
	}
	nullifierRootChain, err := HashChain(inputs.NullifierRoots)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash nullifier root chain: %w", err)
	}
	solanaOwnerKeyHashChain, err := HashChain(inputs.SolanaPkHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash solana pk hash chain: %w", err)
	}
	return HashChain([]*big.Int{
		nullifierChain,
		outputChain,
		utxoRootChain,
		nullifierRootChain,
		inputs.PrivateTxHash,
		inputs.ExternalDataHash,
		inputs.PublicSolAmount,
		inputs.PublicSplAmount,
		inputs.PublicSplAssetPubkey,
		inputs.ProgramIDHashchain,
		inputs.SolanaPubkeyHash,
		inputs.DataHash,
		inputs.PolicyData,
		solanaOwnerKeyHashChain,
	})
}
