package transaction

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

type externalDataPreimage struct {
	InstructionDiscriminator uint8
	ExpiryUnixTs             uint64
	SenderViewTag            [32]byte
	RelayerFee               uint16
	PublicSolAmount          uint64
	PublicSplAmount          uint64
	UserSolAccount           [32]byte
	UserSplToken             [32]byte
	SplTokenInterface        [32]byte
	EncryptedUtxos           []byte
}

type externalValues struct {
	hash            *big.Int
	publicSolAmount *big.Int
	publicSplAmount *big.Int
	publicSplAsset  *big.Int
	// zoneProgramID is the single per-tx zone program identifier (public input).
	// Zero on default transact. dataHash / zoneDataHash are the tx-level
	// program/zone data hashes folded into external_data_hash.
	zoneProgramID *big.Int
	dataHash      *big.Int
	zoneDataHash  *big.Int
}

func buildExternalData(tx ProofTransactionRequest) (externalValues, error) {
	senderViewTag, err := parse.Field(tx.SenderViewTag)
	if err != nil {
		return externalValues{}, fmt.Errorf("sender_view_tag: %w", err)
	}
	// The proved transact path queues the view tag alongside the nullifiers, so
	// it must be in the same indexed-tree domain (0 < v < p - 1) the on-chain
	// queue insert enforces. Reject out-of-domain values here rather than
	// emitting a bundle that proves but is rejected at queue insert.
	if !protocol.InNullifierDomain(senderViewTag) {
		return externalValues{}, fmt.Errorf("sender_view_tag must be in the nullifier tree domain 0 < v < p-1")
	}
	senderViewTagBytes, err := parse.FieldBytes(senderViewTag)
	if err != nil {
		return externalValues{}, fmt.Errorf("sender_view_tag: %w", err)
	}
	encryptedUtxos, err := parse.HexBytes(tx.EncryptedUtxos)
	if err != nil {
		return externalValues{}, fmt.Errorf("encrypted_utxos: %w", err)
	}
	userSolAccount, err := parse.OptionalHex32(tx.UserSolAccount)
	if err != nil {
		return externalValues{}, fmt.Errorf("user_sol_account: %w", err)
	}
	userSplTokenAccount, err := parse.OptionalHex32(tx.UserSplTokenAccount)
	if err != nil {
		return externalValues{}, fmt.Errorf("user_spl_token_account: %w", err)
	}
	splTokenInterface, err := parse.OptionalHex32(tx.SplTokenInterface)
	if err != nil {
		return externalValues{}, fmt.Errorf("spl_token_interface: %w", err)
	}

	publicSolAmount := u64OrZero(tx.PublicSolAmount)
	publicSplAmount := u64OrZero(tx.PublicSplAmount)
	publicAmounts, err := derivePublicAmounts(tx)
	if err != nil {
		return externalValues{}, err
	}
	dataHash, err := parse.OptionalField(tx.DataHash)
	if err != nil {
		return externalValues{}, fmt.Errorf("data_hash: %w", err)
	}
	zoneDataHash, err := parse.OptionalField(tx.ZoneDataHash)
	if err != nil {
		return externalValues{}, fmt.Errorf("zone_data_hash: %w", err)
	}
	// This harness builds only bare default-zone transfers: every UTXO's
	// program/zone fields are zero, so the tx-level program/zone values must be
	// zero too. Reject early with a clear error instead of failing inside the
	// constraint solver.
	if dataHash.Sign() != 0 {
		return externalValues{}, fmt.Errorf("data_hash must be zero: this harness builds only bare default-zone transfers")
	}
	if zoneDataHash.Sign() != 0 {
		return externalValues{}, fmt.Errorf("zone_data_hash must be zero: this harness builds only bare default-zone transfers")
	}
	return externalValues{
		hash: externalDataFieldHash(externalDataPreimage{
			InstructionDiscriminator: tx.InstructionDiscriminator,
			SenderViewTag:            senderViewTagBytes,
			RelayerFee:               tx.RelayerFee,
			ExpiryUnixTs:             tx.ExpiryUnixTs,
			PublicSolAmount:          publicSolAmount,
			PublicSplAmount:          publicSplAmount,
			UserSolAccount:           userSolAccount,
			UserSplToken:             userSplTokenAccount,
			SplTokenInterface:        splTokenInterface,
			EncryptedUtxos:           encryptedUtxos,
		}),
		publicSolAmount: publicAmounts.sol,
		publicSplAmount: publicAmounts.spl,
		publicSplAsset:  publicAmounts.asset,
		zoneProgramID:   big.NewInt(0),
		dataHash:        dataHash,
		zoneDataHash:    zoneDataHash,
	}, nil
}

func externalDataFieldHash(data externalDataPreimage) *big.Int {
	var fee [2]byte
	binary.BigEndian.PutUint16(fee[:], data.RelayerFee)
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], data.ExpiryUnixTs)
	var sol [8]byte
	binary.BigEndian.PutUint64(sol[:], data.PublicSolAmount)
	var spl [8]byte
	binary.BigEndian.PutUint64(spl[:], data.PublicSplAmount)
	// Field order must match the on-chain external_data_hash byte-for-byte
	// (spec: SPP Proof). expiry_unix_ts is bound ONLY here, not in
	// private_tx_hash: SPP can't recompute private_tx_hash (it covers private
	// input hashes), so external_data_hash is what lets SPP confirm the expiry it
	// clock-checks is the one the owner signed.
	return protocol.Sha256BEField(
		[]byte{data.InstructionDiscriminator},
		expiry[:],
		data.SenderViewTag[:],
		fee[:],
		sol[:],
		spl[:],
		data.UserSolAccount[:],
		data.UserSplToken[:],
		data.SplTokenInterface[:],
		data.EncryptedUtxos,
	)
}

func u64OrZero(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}
