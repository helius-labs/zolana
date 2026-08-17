package transaction

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
	mrand "math/rand"

	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/internal/p256key"
	"zolana/prover/prover-test/spp/protocol"
	transfereddsaonly "zolana/prover/prover/transfer_eddsa_only"
)

// Deterministic transaction body used by the proving benchmarks. Fixed values
// keep a benchmark run reproducible: proving cost depends on the shape and the
// variant, never on the particular field values.
const (
	benchZoneProgramID    = 0x5a
	benchNullifierSecret  = 99
	benchExternalDataHash = 300
	benchAsset            = 7
	benchOwnerSeed        = 0x42
	benchPayerSeed        = 0x11
	benchStateLeafBase    = 17
	benchP256Scalar       = 11
)

// benchOwnership selects the ownership layout of a benchmark transaction.
// A non-nil p256OwnerPkHash makes the first input P256-owned, which is what the
// P256 gadget needs to be exercised; every other input stays Solana-owned.
type benchOwnership struct {
	utxoZone        *big.Int
	p256OwnerPkHash *big.Int
}

// benchCore is the variant-independent part of a benchmark transaction: one
// balanced same-asset spend per input slot, no public movement, no dummy or
// address slots.
type benchCore struct {
	inputs             []transfereddsaonly.InputParams
	outputs            []transfereddsaonly.OutputParams
	nullifiers         []*big.Int
	outputHashes       []*big.Int
	utxoTreeRoots      []*big.Int
	nullifierTreeRoots []*big.Int
	published          []*big.Int
	signers            []*big.Int
	spendKey           protocol.SpendKey
	privateTxHash      *big.Int
	externalDataHash   *big.Int
}

// BuildTransferParameters synthesizes a provable witness for one Solana-only
// variant and shape. The parameters are what a client would send: every field
// element is precomputed here, exactly as ProveTransfer expects.
func BuildTransferParameters(
	variant transfereddsaonly.Variant,
	shape protocol.Shape,
) (*transfereddsaonly.TransferParameters, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	publicZone, utxoZone := benchZones(variant)
	core, err := buildBenchCore(shape, benchOwnership{utxoZone: utxoZone})
	if err != nil {
		return nil, err
	}

	params := &transfereddsaonly.TransferParameters{
		NInputs:                      uint32(shape.NInputs),
		NOutputs:                     uint32(shape.NOutputs),
		Inputs:                       core.inputs,
		Outputs:                      core.outputs,
		ExternalDataHash:             core.externalDataHash,
		PrivateTxHash:                core.privateTxHash,
		PublicAssets:                 benchZeroFields(txcircuit.NPublicSlots),
		PublicAmounts:                benchZeroFields(txcircuit.NPublicSlots),
		ZoneProgramID:                publicZone,
		SignerPkHashes:               core.signers,
		AllowDummyInputs:             big.NewInt(1),
		PublishedOutputOwnerPkHashes: core.published,
		Variant:                      variant,
	}
	// The zone authority controls its zone-owned UTXOs: owners neither sign nor
	// publish output tags, so only the payer enters the signer chain.
	if variant == transfereddsaonly.ZoneAuthorityVariant {
		params.SignerPkHashes = core.signers[:1:1]
		params.PublishedOutputOwnerPkHashes = nil
	}

	publicInputHash, err := protocol.PublicInputHash(benchPublicInputs(core, benchPublicTags{
		zoneProgramID:       params.ZoneProgramID,
		allowDummyInputs:    params.AllowDummyInputs,
		signers:             params.SignerPkHashes,
		published:           params.PublishedOutputOwnerPkHashes,
		bindOutputOwnerTags: variant != transfereddsaonly.ZoneAuthorityVariant,
	}))
	if err != nil {
		return nil, fmt.Errorf("spp bench: public input hash: %w", err)
	}
	params.PublicInputHash = publicInputHash
	return params, nil
}

// BuildP256TransferParameters synthesizes a provable witness for the P256
// ownership rail: the first input is P256-owned and its spend is authorized by
// an ECDSA signature over the transaction's private hash.
func BuildP256TransferParameters(shape protocol.Shape) (*transfereddsaonly.P256TransferParameters, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	privateKey, err := p256key.PrivateKeyFromScalar(big.NewInt(benchP256Scalar))
	if err != nil {
		return nil, fmt.Errorf("spp bench: P256 key: %w", err)
	}
	compressed := elliptic.MarshalCompressed(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	ownerPkHash, err := protocol.OwnerPkField(compressed)
	if err != nil {
		return nil, fmt.Errorf("spp bench: P256 owner pk field: %w", err)
	}
	// The P256 rail is a custom-zone circuit, so the transaction carries a zone id
	// while the P256-owned input itself stays outside any zone.
	core, err := buildBenchCore(shape, benchOwnership{
		utxoZone:        big.NewInt(0),
		p256OwnerPkHash: ownerPkHash,
	})
	if err != nil {
		return nil, err
	}

	var privateTxHashBytes [32]byte
	core.privateTxHash.FillBytes(privateTxHashBytes[:])
	digest := sha256.Sum256(privateTxHashBytes[:])
	// A fixed entropy source keeps the signature, and therefore the whole witness,
	// identical across runs. These keys exist only inside benchmarks.
	sigR, sigS, err := ecdsa.Sign(mrand.New(mrand.NewSource(benchP256Scalar)), privateKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("spp bench: P256 signature: %w", err)
	}
	messageHash, err := protocol.HashBytes(digest[:])
	if err != nil {
		return nil, fmt.Errorf("spp bench: P256 message hash: %w", err)
	}

	params := &transfereddsaonly.P256TransferParameters{
		NInputs:                      uint32(shape.NInputs),
		NOutputs:                     uint32(shape.NOutputs),
		Inputs:                       core.inputs,
		Outputs:                      core.outputs,
		ExternalDataHash:             core.externalDataHash,
		PrivateTxHash:                core.privateTxHash,
		P256PubX:                     privateKey.PublicKey.X,
		P256PubY:                     privateKey.PublicKey.Y,
		P256SigR:                     sigR,
		P256SigS:                     sigS,
		P256MessageHashLow:           new(big.Int).SetBytes(digest[16:]),
		P256MessageHashHigh:          new(big.Int).SetBytes(digest[:16]),
		DefaultP256OwnerPkHash:       ownerPkHash,
		PublicAssets:                 benchZeroFields(txcircuit.NPublicSlots),
		PublicAmounts:                benchZeroFields(txcircuit.NPublicSlots),
		ZoneProgramID:                big.NewInt(benchZoneProgramID),
		SignerPkHashes:               core.signers,
		AllowDummyInputs:             big.NewInt(1),
		PublishedOutputOwnerPkHashes: core.published,
	}

	publicInputs := benchPublicInputs(core, benchPublicTags{
		zoneProgramID:       params.ZoneProgramID,
		allowDummyInputs:    params.AllowDummyInputs,
		signers:             params.SignerPkHashes,
		published:           params.PublishedOutputOwnerPkHashes,
		bindOutputOwnerTags: true,
	})
	publicInputHash, err := protocol.PublicInputHashP256(publicInputs, messageHash, ownerPkHash)
	if err != nil {
		return nil, fmt.Errorf("spp bench: P256 public input hash: %w", err)
	}
	params.PublicInputHash = publicInputHash
	return params, nil
}

// benchZones returns the public zone id and the per-UTXO zone id for a variant.
// The confidential rail is non-zone. The custom-zone transfer keeps non-zone
// UTXOs under a zone transaction, which is the configuration the circuit tests
// pin as satisfiable. The authority rail spends zone-owned UTXOs, so their zone
// id must equal the public one.
func benchZones(variant transfereddsaonly.Variant) (publicZone, utxoZone *big.Int) {
	switch variant {
	case transfereddsaonly.ConfidentialVariant:
		return big.NewInt(0), big.NewInt(0)
	case transfereddsaonly.ZoneAuthorityVariant:
		return big.NewInt(benchZoneProgramID), big.NewInt(benchZoneProgramID)
	default:
		return big.NewInt(benchZoneProgramID), big.NewInt(0)
	}
}

func buildBenchCore(shape protocol.Shape, ownership benchOwnership) (benchCore, error) {
	ownerPkHash, err := benchSolanaPkField(benchOwnerSeed)
	if err != nil {
		return benchCore{}, err
	}
	nullifierSecret := big.NewInt(benchNullifierSecret)
	spendKey, err := protocol.NewSpendKey(nullifierSecret)
	if err != nil {
		return benchCore{}, fmt.Errorf("spp bench: spend key: %w", err)
	}
	owner, err := protocol.OwnerHash(ownerPkHash, spendKey.Public)
	if err != nil {
		return benchCore{}, fmt.Errorf("spp bench: owner hash: %w", err)
	}

	inputOwners := make([]*big.Int, shape.NInputs)
	inputOwnerPkHashes := make([]*big.Int, shape.NInputs)
	for i := range inputOwners {
		inputOwners[i] = owner
		inputOwnerPkHashes[i] = ownerPkHash
	}
	// A P256-owned input keeps its owner tag private (zero), so the gadget, not a
	// published Solana signer hash, authorizes the spend.
	if ownership.p256OwnerPkHash != nil {
		if shape.NInputs == 0 {
			return benchCore{}, fmt.Errorf("spp bench: P256 ownership needs at least one input")
		}
		p256Owner, err := protocol.OwnerHash(ownership.p256OwnerPkHash, spendKey.Public)
		if err != nil {
			return benchCore{}, fmt.Errorf("spp bench: P256 owner hash: %w", err)
		}
		inputOwners[0] = p256Owner
		inputOwnerPkHashes[0] = big.NewInt(0)
	}
	inputUtxos, outputUtxos := benchBalancedUtxos(shape, inputOwners, owner, ownership.utxoZone)

	inputHashes := make([]*big.Int, shape.NInputs)
	stateEntries := make(map[uint64]*big.Int, shape.NInputs)
	for i, utxo := range inputUtxos {
		hash, err := protocol.UtxoHash(utxo)
		if err != nil {
			return benchCore{}, fmt.Errorf("spp bench: input %d utxo hash: %w", i, err)
		}
		inputHashes[i] = hash
		stateEntries[benchStateLeafIndex(i)] = hash
	}
	stateRoot, stateProofs, err := protocol.BuildSparseStateTree(stateEntries)
	if err != nil {
		return benchCore{}, fmt.Errorf("spp bench: state tree: %w", err)
	}
	nullifierTree, err := protocol.NewNullifierTree()
	if err != nil {
		return benchCore{}, fmt.Errorf("spp bench: nullifier tree: %w", err)
	}

	core := benchCore{
		inputs:             make([]transfereddsaonly.InputParams, shape.NInputs),
		outputs:            make([]transfereddsaonly.OutputParams, shape.NOutputs),
		nullifiers:         make([]*big.Int, shape.NInputs),
		outputHashes:       make([]*big.Int, shape.NOutputs),
		utxoTreeRoots:      make([]*big.Int, shape.NInputs),
		nullifierTreeRoots: make([]*big.Int, shape.NInputs),
		published:          make([]*big.Int, shape.NOutputs),
		externalDataHash:   big.NewInt(benchExternalDataHash),
	}
	for i, utxo := range inputUtxos {
		stateProof, ok := stateProofs[benchStateLeafIndex(i)]
		if !ok {
			return benchCore{}, fmt.Errorf("spp bench: missing state proof for input %d", i)
		}
		nullifier, err := protocol.Nullifier(inputHashes[i], utxo.Blinding, nullifierSecret)
		if err != nil {
			return benchCore{}, fmt.Errorf("spp bench: input %d nullifier: %w", i, err)
		}
		nonInclusion, err := nullifierTree.NonInclusionWitness(nullifier)
		if err != nil {
			return benchCore{}, fmt.Errorf("spp bench: input %d non-inclusion: %w", i, err)
		}
		core.nullifiers[i] = nullifier
		core.utxoTreeRoots[i] = stateRoot
		core.nullifierTreeRoots[i] = nullifierTree.Root()
		core.inputs[i] = transfereddsaonly.InputParams{
			Utxo:                     benchUtxoParams(utxo),
			IsDummy:                  big.NewInt(0),
			StatePathElements:        stateProof.PathElements,
			StatePathIndex:           new(big.Int).SetUint64(stateProof.PathIndex),
			NullifierLowValue:        nonInclusion.LowValue,
			NullifierNextValue:       nonInclusion.NextValue,
			NullifierLowPathElements: nonInclusion.PathElements,
			NullifierLowPathIndex:    new(big.Int).SetUint64(nonInclusion.LowIndex),
			UtxoTreeRoot:             stateRoot,
			NullifierTreeRoot:        nullifierTree.Root(),
			Nullifier:                nullifier,
			OwnerPkHash:              inputOwnerPkHashes[i],
			NullifierSecret:          nullifierSecret,
			SpendPkX:                 spendKey.Public.X,
			SpendPkY:                 spendKey.Public.Y,
		}
	}

	for i, utxo := range outputUtxos {
		hash, err := protocol.UtxoHash(utxo)
		if err != nil {
			return benchCore{}, fmt.Errorf("spp bench: output %d utxo hash: %w", i, err)
		}
		core.outputHashes[i] = hash
		core.outputs[i] = transfereddsaonly.OutputParams{
			Utxo:        benchUtxoParams(utxo),
			IsDummy:     big.NewInt(0),
			Hash:        hash,
			OwnerPkHash: ownerPkHash,
			SpendPkX:    spendKey.Public.X,
			SpendPkY:    spendKey.Public.Y,
		}
		// Zone-owned outputs keep their owner anonymous, so the published tag is
		// masked to zero.
		if utxo.ZoneProgramID.Sign() == 0 {
			core.published[i] = ownerPkHash
		} else {
			core.published[i] = big.NewInt(0)
		}
	}

	addressHashes := benchZeroFields(shape.NInputs)
	privateTxHash, err := protocol.PrivateTxHash(inputHashes, core.outputHashes, addressHashes, core.externalDataHash)
	if err != nil {
		return benchCore{}, fmt.Errorf("spp bench: private tx hash: %w", err)
	}
	core.privateTxHash = privateTxHash
	core.spendKey = spendKey

	// Second pass: every input signs the transaction's private hash, which only
	// exists once all input and output witnesses are built. Signing per slot
	// keeps two slots of one key from sharing a nonce.
	for i := range core.inputs {
		signature, err := protocol.SignSpend(spendKey, privateTxHash, i)
		if err != nil {
			return benchCore{}, fmt.Errorf("spp bench: input %d spend signature: %w", i, err)
		}
		core.inputs[i].SpendSigX = signature.R.X
		core.inputs[i].SpendSigY = signature.R.Y
		core.inputs[i].SpendSigS = signature.S
	}

	payerPkHash, err := benchSolanaPkField(benchPayerSeed)
	if err != nil {
		return benchCore{}, err
	}
	core.signers = signerPkHashes(payerPkHash, inputOwnerPkHashes)
	return core, nil
}

// benchPublicTags are the variant-dependent tail of the public-input preimage.
type benchPublicTags struct {
	zoneProgramID       *big.Int
	allowDummyInputs    *big.Int
	signers             []*big.Int
	published           []*big.Int
	bindOutputOwnerTags bool
}

// benchPublicInputs mirrors the public-input preimage the circuit recomputes.
// The authority rail omits the output-owner chain; every owner-signed rail
// appends it.
func benchPublicInputs(core benchCore, tags benchPublicTags) protocol.PublicInputs {
	publicInputs := protocol.PublicInputs{
		Nullifiers:          core.nullifiers,
		OutputUtxoHashes:    core.outputHashes,
		UtxoTreeRoots:       core.utxoTreeRoots,
		NullifierTreeRoots:  core.nullifierTreeRoots,
		PrivateTxHash:       core.privateTxHash,
		ExternalDataHash:    core.externalDataHash,
		ZoneProgramID:       tags.zoneProgramID,
		AllowDummyInputs:    tags.allowDummyInputs,
		SignerPkHashes:      tags.signers,
		BindOutputOwnerTags: tags.bindOutputOwnerTags,
		OutputOwnerPkHashes: tags.published,
	}
	for i := 0; i < txcircuit.NPublicSlots; i++ {
		publicInputs.PublicAssets[i] = big.NewInt(0)
		publicInputs.PublicAmounts[i] = big.NewInt(0)
	}
	return publicInputs
}

// benchBalancedUtxos spends one same-asset UTXO per input slot and splits the
// total evenly across the output slots, so the circuit balance check holds with
// no public movement.
func benchBalancedUtxos(
	shape protocol.Shape,
	inputOwners []*big.Int,
	outputOwner *big.Int,
	utxoZone *big.Int,
) ([]protocol.Utxo, []protocol.Utxo) {
	asset := big.NewInt(benchAsset)
	inputs := make([]protocol.Utxo, shape.NInputs)
	total := int64(0)
	for i, owner := range inputOwners {
		amount := int64(100 + i*10)
		inputs[i] = benchUtxo(10+i*10, owner, asset, amount, utxoZone)
		total += amount
	}
	outputs := make([]protocol.Utxo, shape.NOutputs)
	remaining := total
	for i := range outputs {
		amount := remaining / int64(shape.NOutputs-i)
		remaining -= amount
		outputs[i] = benchUtxo(100+i*10, outputOwner, asset, amount, utxoZone)
	}
	return inputs, outputs
}

func benchUtxo(base int, owner, asset *big.Int, amount int64, utxoZone *big.Int) protocol.Utxo {
	return protocol.Utxo{
		Domain:        big.NewInt(protocol.UtxoDomain),
		Owner:         new(big.Int).Set(owner),
		Asset:         new(big.Int).Set(asset),
		Amount:        big.NewInt(amount),
		Blinding:      big.NewInt(int64(base + 5)),
		DataHash:      big.NewInt(0),
		ZoneDataHash:  big.NewInt(0),
		ZoneProgramID: new(big.Int).Set(utxoZone),
	}
}

func benchUtxoParams(utxo protocol.Utxo) transfereddsaonly.UtxoParams {
	return transfereddsaonly.UtxoParams{
		Domain:        utxo.Domain,
		Owner:         utxo.Owner,
		Asset:         utxo.Asset,
		Amount:        utxo.Amount,
		Blinding:      utxo.Blinding,
		DataHash:      utxo.DataHash,
		ZoneDataHash:  utxo.ZoneDataHash,
		ZoneProgramID: utxo.ZoneProgramID,
	}
}

// benchSolanaPkField derives a pk_field from a deterministic 32-byte pubkey.
func benchSolanaPkField(seed byte) (*big.Int, error) {
	var pubkey [32]byte
	for i := range pubkey {
		pubkey[i] = seed
	}
	pkField, err := protocol.SolanaPkField(pubkey)
	if err != nil {
		return nil, fmt.Errorf("spp bench: solana pk field: %w", err)
	}
	return pkField, nil
}

func benchStateLeafIndex(i int) uint64 {
	return uint64(benchStateLeafBase + i)
}

func benchZeroFields(length int) []*big.Int {
	out := make([]*big.Int, length)
	for i := range out {
		out[i] = big.NewInt(0)
	}
	return out
}
