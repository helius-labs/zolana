package transaction

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"light/light-prover/prover/spp/parse"
	"light/light-prover/prover/spp/protocol"
)

type externalDataPreimage struct {
	InstructionDiscriminator uint8
	SenderViewTag            [32]byte
	RelayerFee               uint16
	ExpiryUnixTs             uint64
	PublicSolAmount          uint64
	PublicSplAmount          uint64
	UserSolAccount           [32]byte
	UserSplToken             [32]byte
	SplTokenInterface        [32]byte
	EncryptedUtxos           []byte
}

type externalValues struct {
	hash               *big.Int
	expiry             *big.Int
	publicSolAmount    *big.Int
	publicSplAmount    *big.Int
	publicSplAsset     *big.Int
	programIDHashchain *big.Int
	dataHash           *big.Int
	zoneDataHash       *big.Int
}

func buildExternalData(tx ProofTransactionRequest) (externalValues, error) {
	senderViewTag, err := parse.Field(tx.SenderViewTag)
	if err != nil {
		return externalValues{}, fmt.Errorf("sender_view_tag: %w", err)
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
	programIDHashchain, err := parse.OptionalField(tx.ProgramIDHashchain)
	if err != nil {
		return externalValues{}, fmt.Errorf("program_id_hashchain: %w", err)
	}
	dataHash, err := parse.OptionalField(tx.DataHash)
	if err != nil {
		return externalValues{}, fmt.Errorf("data_hash: %w", err)
	}
	zoneDataHash, err := parse.OptionalField(tx.ZoneDataHash)
	if err != nil {
		return externalValues{}, fmt.Errorf("zone_data_hash: %w", err)
	}
	// TODO(zones): wire program_id_hashchain/data_hash/zone_data_hash on-chain (proof.rs hardcodes EMPTY_FIELD); until then non-zero values won't verify.
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
		expiry:             new(big.Int).SetUint64(tx.ExpiryUnixTs),
		publicSolAmount:    publicAmounts.sol,
		publicSplAmount:    publicAmounts.spl,
		publicSplAsset:     publicAmounts.asset,
		programIDHashchain: programIDHashchain,
		dataHash:           dataHash,
		zoneDataHash:       zoneDataHash,
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
	// Field order is part of the transcript; it must match the on-chain
	// external_data_hash byte-for-byte. expiry_unix_ts is included so the
	// on-chain expiry check binds to the proof.
	return protocol.Sha256BEField(
		[]byte{data.InstructionDiscriminator},
		data.SenderViewTag[:],
		fee[:],
		expiry[:],
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
