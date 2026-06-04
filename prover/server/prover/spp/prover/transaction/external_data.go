package transaction

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"light/light-prover/prover/spp/parse"
)

type externalDataPreimage struct {
	InstructionDiscriminator uint8
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

	return externalValues{
		hash: externalDataFieldHash(externalDataPreimage{
			InstructionDiscriminator: tx.InstructionDiscriminator,
			SenderViewTag:            senderViewTagBytes,
			RelayerFee:               tx.RelayerFee,
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
	hasher := sha256.New()
	hasher.Write([]byte{data.InstructionDiscriminator})
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
	sum := hasher.Sum(nil)
	sum[0] = 0
	return new(big.Int).SetBytes(sum)
}

func u64OrZero(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}
