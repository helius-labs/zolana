package spp

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
)

// buildExternalDataHash parses the instruction-bound fields of tx and folds them
// into external_data_hash, the value the on-chain SPP recomputes from
// instruction data and account state.
func buildExternalDataHash(tx ProofTransactionRequest) (*big.Int, error) {
	senderViewTag, err := parseField(tx.SenderViewTag)
	if err != nil {
		return nil, fmt.Errorf("sender_view_tag: %w", err)
	}
	encryptedUtxos, err := parseHexBytes(tx.EncryptedUtxos)
	if err != nil {
		return nil, fmt.Errorf("encrypted_utxos: %w", err)
	}
	userSolAccount, err := parseOptionalHex32(tx.UserSolAccount)
	if err != nil {
		return nil, fmt.Errorf("user_sol_account: %w", err)
	}
	userSplTokenAccount, err := parseOptionalHex32(tx.UserSplTokenAccount)
	if err != nil {
		return nil, fmt.Errorf("user_spl_token_account: %w", err)
	}
	splTokenInterface, err := parseOptionalHex32(tx.SplTokenInterface)
	if err != nil {
		return nil, fmt.Errorf("spl_token_interface: %w", err)
	}
	return proofExternalDataFieldHash(proofExternalData{
		InstructionDiscriminator: tx.InstructionDiscriminator,
		ExpiryUnixTs:             tx.ExpiryUnixTs,
		SenderViewTag:            proofFieldBytes(senderViewTag),
		RelayerFee:               tx.RelayerFee,
		PublicSolAmount:          optionalU64(tx.PublicSolAmount),
		PublicSplAmount:          optionalU64(tx.PublicSplAmount),
		UserSolAccount:           userSolAccount,
		UserSplToken:             userSplTokenAccount,
		SplTokenInterface:        splTokenInterface,
		EncryptedUtxos:           encryptedUtxos,
	}), nil
}

// proofExternalData is the instruction-bound data the on-chain SPP recomputes
// and folds into external_data_hash. Field order here is the byte order hashed
// by proofExternalDataFieldHash.
type proofExternalData struct {
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

// proofExternalDataFieldHash is Sha256BE of the instruction-bound data: the
// fields are written in struct order and the top byte of the digest is zeroed so
// the result fits a BN254 field element. The on-chain SPP recomputes this from
// instruction data and account state.
func proofExternalDataFieldHash(data proofExternalData) *big.Int {
	hasher := sha256.New()
	hasher.Write([]byte{data.InstructionDiscriminator})
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], data.ExpiryUnixTs)
	hasher.Write(expiry[:])
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
