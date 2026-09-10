package transaction

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

type interfaceTransferKind uint8

const (
	interfaceTransferSolDeposit interfaceTransferKind = iota
	interfaceTransferSolWithdrawal
	interfaceTransferSplDeposit
	interfaceTransferSplWithdrawal
)

type interfaceTransferData struct {
	kind              interfaceTransferKind
	amount            uint64
	splInterfaceBump  uint8
	userAccount       [32]byte
	splTokenInterface [32]byte
}

type ownerTagKind uint8

const (
	ownerTagInline ownerTagKind = iota
	ownerTagAccount
)

type ownerTagData struct {
	kind           ownerTagKind
	inline         [32]byte
	accountIndex   uint8
	accountAddress [32]byte
}

type transactOutputData struct {
	utxoHash    [32]byte
	ownerTag    ownerTagData
	dataPresent bool
	data        []byte
}

type transactMessageData struct {
	viewTag [32]byte
	data    []byte
}

// externalDataHashInput is the flat instruction prefix followed by the client
// context needed to resolve account-backed values. The encoder below writes
// exactly the first eight fields of Rust TransactIxData; account addresses are
// deliberately excluded from that prefix and appended separately by
// externalDataHash.
type externalDataHashInput struct {
	instructionDiscriminator uint8
	expiryUnixTs             uint64
	txViewingPk              [33]byte
	salt                     [16]byte
	interfaceTransfers       []interfaceTransferData
	dataHashPresent          bool
	dataHash                 [32]byte
	ringDataHashPresent      bool
	ringDataHash             [32]byte
	outputs                  []transactOutputData
	messages                 []transactMessageData
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
	interfaceTransfers, err := buildInterfaceTransfers(tx.InterfaceTransfers)
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
	outputs, err := buildTransactOutputs(outputHashes, senderViewTagBytes, encryptedUtxos)
	if err != nil {
		return externalValues{}, err
	}
	externalDataHashBytes, err := externalDataHash(externalDataHashInput{
		instructionDiscriminator: tx.InstructionDiscriminator,
		expiryUnixTs:             tx.ExpiryUnixTs,
		txViewingPk:              txViewingPk,
		salt:                     salt,
		interfaceTransfers:       interfaceTransfers,
		// This harness only accepts bare default-ring transfers, so both
		// transaction-level hashes are canonically None. The parsed zero
		// values above are circuit fields, not present Option values.
		outputs: outputs,
	})
	if err != nil {
		return externalValues{}, fmt.Errorf("external_data_hash: %w", err)
	}
	return externalValues{
		hash:        new(big.Int).SetBytes(externalDataHashBytes[:]),
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

func buildTransactOutputs(outputHashes []*big.Int, ownerTag [32]byte, encryptedUtxos []byte) ([]transactOutputData, error) {
	outputs := make([]transactOutputData, 0, len(outputHashes))
	for position, hash := range outputHashes {
		hashBytes, err := parse.FieldBytes(hash)
		if err != nil {
			return nil, fmt.Errorf("output hash %d: %w", position, err)
		}
		output := transactOutputData{
			utxoHash: hashBytes,
			ownerTag: ownerTagData{
				kind:   ownerTagInline,
				inline: ownerTag,
			},
		}
		if position == 0 {
			// The current request format carries one sender ciphertext bundle.
			// It is attached to the first output exactly like Some(data) in the
			// Rust TransactOutput; every following output carries None. The flag
			// is separate because Some(empty) must not collide with None.
			output.dataPresent = true
			output.data = encryptedUtxos
		}
		outputs = append(outputs, output)
	}
	return outputs, nil
}

func buildInterfaceTransfers(transfers []InterfaceTransferRequest) ([]interfaceTransferData, error) {
	built := make([]interfaceTransferData, 0, len(transfers))
	for position, transfer := range transfers {
		userAccount, err := parse.Hex32(transfer.UserAccount)
		if err != nil {
			return nil, fmt.Errorf("interface_transfers[%d].user_account: %w", position, err)
		}
		kind := interfaceTransferSolWithdrawal
		if transfer.IsDeposit {
			kind = interfaceTransferSolDeposit
		}
		interfaceTransfer := interfaceTransferData{
			kind:        kind,
			amount:      transfer.Amount,
			userAccount: userAccount,
		}
		if transfer.IsSpl {
			splTokenInterface, err := parse.Hex32(transfer.PoolAccount)
			if err != nil {
				return nil, fmt.Errorf("interface_transfers[%d].pool_account: %w", position, err)
			}
			interfaceTransfer.kind = interfaceTransferSplWithdrawal
			if transfer.IsDeposit {
				interfaceTransfer.kind = interfaceTransferSplDeposit
			}
			interfaceTransfer.splInterfaceBump = transfer.SplInterfaceBump
			interfaceTransfer.splTokenInterface = splTokenInterface
		} else {
			if transfer.PoolAccount != "" {
				return nil, fmt.Errorf("interface_transfers[%d].pool_account must be empty for SOL", position)
			}
			if transfer.SplInterfaceBump != 0 {
				return nil, fmt.Errorf("interface_transfers[%d].spl_interface_bump must be zero for SOL", position)
			}
		}
		built = append(built, interfaceTransfer)
	}
	return built, nil
}

func externalDataHash(data externalDataHashInput) ([32]byte, error) {
	prefix, err := encodeExternalDataPrefix(data)
	if err != nil {
		return [32]byte{}, err
	}

	// Append settlement and account-backed owner addresses directly after the
	// prefix, in protocol order. Deriving that order from the same
	// transfer/output values that produced the prefix prevents an independent
	// address list from drifting out of sync.
	preimage := make([]byte, 0, 1+len(prefix))
	preimage = append(preimage, data.instructionDiscriminator)
	preimage = append(preimage, prefix...)
	for _, transfer := range data.interfaceTransfers {
		preimage = append(preimage, transfer.userAccount[:]...)
		if transfer.kind == interfaceTransferSplDeposit || transfer.kind == interfaceTransferSplWithdrawal {
			preimage = append(preimage, transfer.splTokenInterface[:]...)
		}
	}
	for _, output := range data.outputs {
		if output.ownerTag.kind == ownerTagAccount {
			preimage = append(preimage, output.ownerTag.accountAddress[:]...)
		}
	}

	digest := sha256.Sum256(preimage)
	// Sha256BE maps the digest into the BN254 field by clearing its most
	// significant byte.
	digest[0] = 0
	return digest, nil
}

func encodeExternalDataPrefix(data externalDataHashInput) ([]byte, error) {
	if len(data.interfaceTransfers) > MaxInterfaceTransfers {
		return nil, fmt.Errorf("interface transfer count %d exceeds protocol maximum %d", len(data.interfaceTransfers), MaxInterfaceTransfers)
	}
	if len(data.outputs) > 255 {
		return nil, fmt.Errorf("output count %d exceeds u8", len(data.outputs))
	}
	if len(data.messages) > 255 {
		return nil, fmt.Errorf("message count %d exceeds u8", len(data.messages))
	}

	prefix := make([]byte, 0, 8+33+16+1+1+1+1)
	prefix = binary.LittleEndian.AppendUint64(prefix, data.expiryUnixTs)
	prefix = append(prefix, data.txViewingPk[:]...)
	prefix = append(prefix, data.salt[:]...)
	prefix = append(prefix, byte(len(data.interfaceTransfers)))
	for position, transfer := range data.interfaceTransfers {
		if transfer.amount == 0 {
			return nil, fmt.Errorf("interface transfer %d amount must be nonzero", position)
		}
		switch transfer.kind {
		case interfaceTransferSolDeposit, interfaceTransferSolWithdrawal:
			prefix = append(prefix, byte(transfer.kind))
			prefix = binary.LittleEndian.AppendUint64(prefix, transfer.amount)
		case interfaceTransferSplDeposit, interfaceTransferSplWithdrawal:
			prefix = append(prefix, byte(transfer.kind))
			prefix = binary.LittleEndian.AppendUint64(prefix, transfer.amount)
			prefix = append(prefix, transfer.splInterfaceBump)
		default:
			return nil, fmt.Errorf("interface transfer %d has invalid kind %d", position, transfer.kind)
		}
	}
	prefix = appendOptionalHash(prefix, data.dataHashPresent, data.dataHash)
	prefix = appendOptionalHash(prefix, data.ringDataHashPresent, data.ringDataHash)
	prefix = append(prefix, byte(len(data.outputs)))
	for position, output := range data.outputs {
		prefix = append(prefix, output.utxoHash[:]...)
		switch output.ownerTag.kind {
		case ownerTagInline:
			prefix = append(prefix, byte(ownerTagInline))
			prefix = append(prefix, output.ownerTag.inline[:]...)
		case ownerTagAccount:
			prefix = append(prefix, byte(ownerTagAccount), output.ownerTag.accountIndex)
		default:
			return nil, fmt.Errorf("output %d has invalid owner tag kind %d", position, output.ownerTag.kind)
		}
		if !output.dataPresent {
			prefix = append(prefix, 0)
			continue
		}
		if len(output.data) > 1<<16-1 {
			return nil, fmt.Errorf("output %d data length %d exceeds u16", position, len(output.data))
		}
		prefix = append(prefix, 1)
		prefix = binary.LittleEndian.AppendUint16(prefix, uint16(len(output.data)))
		prefix = append(prefix, output.data...)
	}
	prefix = append(prefix, byte(len(data.messages)))
	for position, message := range data.messages {
		if len(message.data) > 1<<16-1 {
			return nil, fmt.Errorf("message %d data length %d exceeds u16", position, len(message.data))
		}
		prefix = append(prefix, message.viewTag[:]...)
		prefix = binary.LittleEndian.AppendUint16(prefix, uint16(len(message.data)))
		prefix = append(prefix, message.data...)
	}
	return prefix, nil
}

func appendOptionalHash(dst []byte, present bool, value [32]byte) []byte {
	if !present {
		return append(dst, 0)
	}
	dst = append(dst, 1)
	return append(dst, value[:]...)
}
