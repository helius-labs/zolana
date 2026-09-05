package protocol

import (
	"fmt"
	"math/big"

	"zolana/prover/prover-test/poseidon"
)

// solAssetValue is the UTXO asset field for native SOL: the default (all-zero)
// address encoded like any fixed 32-byte Address in a UTXO commitment:
// HashBytes([0; 32]) == Poseidon(0, 0). Spec: SOL is Address::default(), and the SPL
// asset uses the same SolanaPkField encoding (on-chain public_spl_asset).
var solAssetValue = mustSolAsset()

func mustSolAsset() *big.Int {
	asset, err := SolanaPkField([32]byte{})
	if err != nil {
		panic(err)
	}
	return asset
}

// SolAsset returns the native-SOL asset field used in UTXO commitments and the
// balance check.
func SolAsset() *big.Int {
	return new(big.Int).Set(solAssetValue)
}

// UTXO domain tags: the circuit classifies input and output slots by the
// domain tag alone (mirrors circuits/spp_transaction/shared).
const (
	DummyDomain   = 1
	AddressDomain = 2
	UtxoDomain    = 3
	// OutputBlindingDomainV1 is the ASCII tag "TXOB".
	OutputBlindingDomainV1 = 0x54584f42
	// OutputBlindingSeedDomainV1 is the ASCII tag "TXOS".
	OutputBlindingSeedDomainV1 = 0x54584f53
	// PrivateTxBlindingDomainV1 is the ASCII tag "TXPB".
	PrivateTxBlindingDomainV1 = 0x54585042
)

// A transaction draws one secret, txSecret, and derives every other
// per-transaction secret from it and the first nullifier. A nullifier enters
// the nullifier tree once, so each child is unique to one accepted
// transaction even if a client reuses a secret.
//
// The children are domain-separated because they are disclosed to different
// parties: OutputBlindingSeed goes to the reader of an anonymous Sender bundle
// or a plaintext transfer, PrivateTxBlinding goes to a policy or third-party
// co-prover. Neither can invert its child to txSecret, so neither can reach
// the other's. txSecret itself is disclosed to nobody.

// OutputBlindingSeed derives the seed every physical output blinding comes
// from. This value is disclosed by the layouts that describe several slots
// from one payload; the derived blindings are what other layouts carry.
func OutputBlindingSeed(firstNullifier, txSecret *big.Int) (*big.Int, error) {
	h, err := poseidon.Hash([]*big.Int{
		big.NewInt(OutputBlindingSeedDomainV1),
		firstNullifier,
		txSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("spp: output blinding seed: %w", err)
	}
	return h, nil
}

// PrivateTxBlinding derives the final private_tx_hash preimage element, shared
// by the transfer and merge rails. It is never published: every other preimage
// element is public or computable, so a known blinding would let an observer
// test candidate input UTXO hashes against the published hash.
func PrivateTxBlinding(firstNullifier, txSecret *big.Int) (*big.Int, error) {
	h, err := poseidon.Hash([]*big.Int{
		big.NewInt(PrivateTxBlindingDomainV1),
		firstNullifier,
		txSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("spp: private tx blinding: %w", err)
	}
	return h, nil
}

// OutputBlinding derives one physical SPP transaction output blinding.
func OutputBlinding(firstNullifier, seed *big.Int, outputIndex int) (*big.Int, error) {
	h, err := poseidon.Hash([]*big.Int{
		big.NewInt(OutputBlindingDomainV1),
		firstNullifier,
		seed,
		big.NewInt(int64(outputIndex)),
	})
	if err != nil {
		return nil, fmt.Errorf("spp: output blinding: %w", err)
	}
	return h, nil
}

type Utxo struct {
	Domain        *big.Int
	Owner         *big.Int
	Asset         *big.Int
	Amount        *big.Int
	Blinding      *big.Int
	DataHash      *big.Int
	RingDataHash  *big.Int
	RingProgramID *big.Int
}

// OwnerUtxoHash nests the owner and blinding into a single field,
// owner_utxo_hash = Poseidon(owner, blinding). The UTXO commitment carries this
// instead of owner+blinding directly, so a proofless deposit can commit to a
// recipient without revealing the owner. The spend circuit re-derives it from
// the (private) owner and blinding witnesses.
func OwnerUtxoHash(owner, blinding *big.Int) (*big.Int, error) {
	h, err := poseidon.Hash([]*big.Int{owner, blinding})
	if err != nil {
		return nil, fmt.Errorf("spp: owner utxo hash: %w", err)
	}
	return h, nil
}

func UtxoHash(u Utxo) (*big.Int, error) {
	ownerUtxoHash, err := OwnerUtxoHash(u.Owner, u.Blinding)
	if err != nil {
		return nil, err
	}
	ringHash, err := poseidon.Hash([]*big.Int{u.RingDataHash, u.RingProgramID})
	if err != nil {
		return nil, fmt.Errorf("spp: ring hash: %w", err)
	}
	h, err := poseidon.Hash([]*big.Int{
		u.Domain,
		u.Asset,
		u.Amount,
		u.DataHash,
		ringHash,
		ownerUtxoHash,
	})
	if err != nil {
		return nil, fmt.Errorf("spp: utxo hash: %w", err)
	}
	return h, nil
}

func Nullifier(utxoHash, blinding, nullifierSecret *big.Int) (*big.Int, error) {
	h, err := poseidon.Hash([]*big.Int{utxoHash, blinding, nullifierSecret})
	if err != nil {
		return nil, fmt.Errorf("spp: nullifier hash: %w", err)
	}
	return h, nil
}

func NullifierFromSecret(utxo Utxo, nullifierSecret *big.Int) (*big.Int, error) {
	utxoHash, err := UtxoHash(utxo)
	if err != nil {
		return nil, err
	}
	return Nullifier(utxoHash, utxo.Blinding, nullifierSecret)
}
