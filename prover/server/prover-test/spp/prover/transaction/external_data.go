package transaction

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

type externalDataPreimage struct {
	InstructionDiscriminator uint8
	ExpiryUnixTs             uint64
	TxViewingPk              [33]byte
	Salt                     [16]byte
	InterfaceTransfers       []resolvedInterfaceTransfer
	DataHashPresent          bool
	DataHash                 [32]byte
	RingDataHashPresent      bool
	RingDataHash             [32]byte
	Outputs                  []resolvedOutput
	Messages                 []resolvedMessage
}

type resolvedInterfaceTransfer struct {
	isSpl            bool
	isDeposit        bool
	amount           uint64
	splInterfaceBump uint8
	asset            [32]byte
	userAccount      [32]byte
}

type resolvedOutput struct {
	utxoHash [32]byte
	ownerTag [32]byte
	hasData  bool
	data     []byte
}

type resolvedMessage struct {
	viewTag [32]byte
	data    []byte
}

const (
	solDepositVariant    byte = 0
	solWithdrawalVariant byte = 1
	splDepositVariant    byte = 2
	splWithdrawalVariant byte = 3

	inlineOwnerTagVariant byte = 0

	optionAbsent  byte = 0
	optionPresent byte = 1
)

func (transfer resolvedInterfaceTransfer) variant() byte {
	switch {
	case transfer.isSpl && transfer.isDeposit:
		return splDepositVariant
	case transfer.isSpl:
		return splWithdrawalVariant
	case transfer.isDeposit:
		return solDepositVariant
	default:
		return solWithdrawalVariant
	}
}

type externalValues struct {
	hash        *big.Int
	publicSlots publicSlots
	// ringProgramID is the single per-tx ring program identifier (public input).
	// Zero on default transact. dataHash / ringDataHash are the tx-level
	// program/ring data hashes folded into external_data_hash.
	ringProgramID *big.Int
	dataHash      *big.Int
	ringDataHash  *big.Int
}

func buildExternalData(tx ProofTransactionRequest, outputHashes []*big.Int) (externalValues, error) {
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
	slots, err := derivePublicSlots(tx)
	if err != nil {
		return externalValues{}, err
	}
	interfaceTransfers, err := resolveInterfaceTransfers(tx.InterfaceTransfers)
	if err != nil {
		return externalValues{}, err
	}
	dataHash, err := parse.OptionalField(tx.DataHash)
	if err != nil {
		return externalValues{}, fmt.Errorf("data_hash: %w", err)
	}
	ringDataHash, err := parse.OptionalField(tx.RingDataHash)
	if err != nil {
		return externalValues{}, fmt.Errorf("ring_data_hash: %w", err)
	}
	// This harness builds only bare default-ring transfers: every UTXO's
	// program/ring fields are zero, so the tx-level program/ring values must be
	// zero too. Reject early with a clear error instead of failing inside the
	// constraint solver.
	if dataHash.Sign() != 0 {
		return externalValues{}, fmt.Errorf("data_hash must be zero: this harness builds only bare default-ring transfers")
	}
	if ringDataHash.Sign() != 0 {
		return externalValues{}, fmt.Errorf("ring_data_hash must be zero: this harness builds only bare default-ring transfers")
	}
	dataHashBytes, err := parse.FieldBytes(dataHash)
	if err != nil {
		return externalValues{}, fmt.Errorf("data_hash: %w", err)
	}
	ringDataHashBytes, err := parse.FieldBytes(ringDataHash)
	if err != nil {
		return externalValues{}, fmt.Errorf("ring_data_hash: %w", err)
	}
	txViewingPkBytes, err := fixedHexBytes(tx.TxViewingPk, 33)
	if err != nil {
		return externalValues{}, fmt.Errorf("tx_viewing_pk: %w", err)
	}
	var txViewingPk [33]byte
	copy(txViewingPk[:], txViewingPkBytes)
	saltBytes, err := fixedHexBytes(tx.Salt, 16)
	if err != nil {
		return externalValues{}, fmt.Errorf("salt: %w", err)
	}
	var salt [16]byte
	copy(salt[:], saltBytes)
	outputs, err := resolveOutputs(outputHashes, senderViewTagBytes, encryptedUtxos)
	if err != nil {
		return externalValues{}, err
	}
	return externalValues{
		hash: externalDataFieldHash(externalDataPreimage{
			InstructionDiscriminator: tx.InstructionDiscriminator,
			ExpiryUnixTs:             tx.ExpiryUnixTs,
			TxViewingPk:              txViewingPk,
			Salt:                     salt,
			InterfaceTransfers:       interfaceTransfers,
			DataHashPresent:          false,
			DataHash:                 dataHashBytes,
			RingDataHashPresent:      false,
			RingDataHash:             ringDataHashBytes,
			Outputs:                  outputs,
			Messages:                 nil,
		}),
		publicSlots: slots,
		// The custom-ring circuits assert the public ring id is
		// nonzero: on-chain they are reachable only via ring_transact, whose
		// ring id comes from the validated RingConfig and is never 0. The
		// harness models bare UTXOs, which stay member-or-free under any id.
		ringProgramID: big.NewInt(1),
		dataHash:      dataHash,
		ringDataHash:  ringDataHash,
	}, nil
}

func fixedHexBytes(value string, size int) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return make([]byte, size), nil
	}
	decoded, err := parse.HexBytes(value)
	if err != nil {
		return nil, err
	}
	if len(decoded) != size {
		return nil, fmt.Errorf("expected %d bytes, got %d", size, len(decoded))
	}
	return decoded, nil
}

func resolveOutputs(outputHashes []*big.Int, ownerTag [32]byte, encryptedUtxos []byte) ([]resolvedOutput, error) {
	outputs := make([]resolvedOutput, 0, len(outputHashes))
	for position, hash := range outputHashes {
		hashBytes, err := parse.FieldBytes(hash)
		if err != nil {
			return nil, fmt.Errorf("output hash %d: %w", position, err)
		}
		output := resolvedOutput{
			utxoHash: hashBytes,
			ownerTag: ownerTag,
		}
		if position == 0 {
			output.hasData = true
			output.data = encryptedUtxos
		}
		outputs = append(outputs, output)
	}
	return outputs, nil
}

func resolveInterfaceTransfers(transfers []InterfaceTransferRequest) ([]resolvedInterfaceTransfer, error) {
	resolved := make([]resolvedInterfaceTransfer, 0, len(transfers))
	for position, transfer := range transfers {
		userAccount, err := parse.Hex32(transfer.UserAccount)
		if err != nil {
			return nil, fmt.Errorf("interface_transfers[%d].user_account: %w", position, err)
		}
		asset, err := interfaceTransferAssetAddress(transfer, position)
		if err != nil {
			return nil, err
		}
		if !transfer.IsSpl && transfer.SplInterfaceBump != 0 {
			return nil, fmt.Errorf("interface_transfers[%d].spl_interface_bump must be zero for SOL", position)
		}
		resolved = append(resolved, resolvedInterfaceTransfer{
			isSpl:            transfer.IsSpl,
			isDeposit:        transfer.IsDeposit,
			amount:           transfer.Amount,
			splInterfaceBump: transfer.SplInterfaceBump,
			asset:            asset,
			userAccount:      userAccount,
		})
	}
	return resolved, nil
}

func interfaceTransferAssetAddress(transfer InterfaceTransferRequest, position int) ([32]byte, error) {
	if !transfer.IsSpl {
		if transfer.Asset != "" {
			return [32]byte{}, fmt.Errorf("interface_transfers[%d].asset must be empty for SOL", position)
		}
		return protocol.SolInterface, nil
	}
	mint, err := parse.Hex32(transfer.Asset)
	if err != nil {
		return [32]byte{}, fmt.Errorf("interface_transfers[%d].asset: %w", position, err)
	}
	return mint, nil
}

func externalDataPrefixBytes(data externalDataPreimage) []byte {
	prefix := binary.LittleEndian.AppendUint64(nil, data.ExpiryUnixTs)
	prefix = append(prefix, data.TxViewingPk[:]...)
	prefix = append(prefix, data.Salt[:]...)
	prefix = append(prefix, byte(len(data.InterfaceTransfers)))
	for _, leg := range data.InterfaceTransfers {
		prefix = append(prefix, leg.variant())
		prefix = binary.LittleEndian.AppendUint64(prefix, leg.amount)
		if leg.isSpl {
			prefix = append(prefix, leg.splInterfaceBump)
		}
	}
	prefix = appendOptionalHash(prefix, data.DataHashPresent, data.DataHash)
	prefix = appendOptionalHash(prefix, data.RingDataHashPresent, data.RingDataHash)
	prefix = append(prefix, byte(len(data.Outputs)))
	for _, output := range data.Outputs {
		prefix = append(prefix, output.utxoHash[:]...)
		prefix = append(prefix, inlineOwnerTagVariant)
		prefix = append(prefix, output.ownerTag[:]...)
		if !output.hasData {
			prefix = append(prefix, optionAbsent)
			continue
		}
		prefix = append(prefix, optionPresent)
		prefix = binary.LittleEndian.AppendUint16(prefix, uint16(len(output.data)))
		prefix = append(prefix, output.data...)
	}
	prefix = append(prefix, byte(len(data.Messages)))
	for _, message := range data.Messages {
		prefix = append(prefix, message.viewTag[:]...)
		prefix = binary.LittleEndian.AppendUint16(prefix, uint16(len(message.data)))
		prefix = append(prefix, message.data...)
	}
	return prefix
}

func appendOptionalHash(prefix []byte, present bool, hash [32]byte) []byte {
	if !present {
		return append(prefix, optionAbsent)
	}
	prefix = append(prefix, optionPresent)
	return append(prefix, hash[:]...)
}

func externalDataFieldHash(data externalDataPreimage) *big.Int {
	preimage := [][]byte{{data.InstructionDiscriminator}, externalDataPrefixBytes(data)}
	for _, leg := range data.InterfaceTransfers {
		preimage = append(preimage, leg.asset[:], leg.userAccount[:])
	}
	return protocol.Sha256BEField(preimage...)
}
