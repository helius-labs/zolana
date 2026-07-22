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
	PublicLegs               []resolvedPublicLeg
	DataHash                 [32]byte
	ZoneDataHash             [32]byte
	Outputs                  []resolvedOutput
	Messages                 []resolvedMessage
}

type resolvedPublicLeg struct {
	isSpl       bool
	isDeposit   bool
	amount      uint64
	userAccount [32]byte
	poolAccount [32]byte
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

type externalValues struct {
	hash        *big.Int
	publicSlots publicSlots
	// zoneProgramID is the single per-tx zone program identifier (public input).
	// Zero on default transact. dataHash / zoneDataHash are the tx-level
	// program/zone data hashes folded into external_data_hash.
	zoneProgramID *big.Int
	dataHash      *big.Int
	zoneDataHash  *big.Int
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
	publicLegs, err := resolvePublicLegs(tx.PublicLegs)
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
	dataHashBytes, err := parse.FieldBytes(dataHash)
	if err != nil {
		return externalValues{}, fmt.Errorf("data_hash: %w", err)
	}
	zoneDataHashBytes, err := parse.FieldBytes(zoneDataHash)
	if err != nil {
		return externalValues{}, fmt.Errorf("zone_data_hash: %w", err)
	}
	outputs, err := resolveOutputs(outputHashes, senderViewTagBytes, encryptedUtxos)
	if err != nil {
		return externalValues{}, err
	}
	return externalValues{
		hash: externalDataFieldHash(externalDataPreimage{
			InstructionDiscriminator: tx.InstructionDiscriminator,
			ExpiryUnixTs:             tx.ExpiryUnixTs,
			PublicLegs:               publicLegs,
			DataHash:                 dataHashBytes,
			ZoneDataHash:             zoneDataHashBytes,
			Outputs:                  outputs,
			Messages:                 nil,
		}),
		publicSlots: slots,
		// The anonymous (custom-zone) circuits assert the public zone id is
		// nonzero: on-chain they are reachable only via zone_transact, whose
		// zone id comes from the validated ZoneConfig and is never 0. The
		// harness models bare UTXOs, which stay member-or-free under any id.
		zoneProgramID: big.NewInt(1),
		dataHash:      dataHash,
		zoneDataHash:  zoneDataHash,
	}, nil
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
			// The current request format carries one sender ciphertext bundle.
			// It is attached to the first output exactly like Some(data) in the
			// Rust TransactOutput; every following output carries None. hasData
			// is separate because Some(empty) must not collide with None.
			output.hasData = true
			output.data = encryptedUtxos
		}
		outputs = append(outputs, output)
	}
	return outputs, nil
}

func resolvePublicLegs(legs []PublicLegRequest) ([]resolvedPublicLeg, error) {
	resolved := make([]resolvedPublicLeg, 0, len(legs))
	for position, leg := range legs {
		userAccount, err := parse.Hex32(leg.UserAccount)
		if err != nil {
			return nil, fmt.Errorf("public_legs[%d].user_account: %w", position, err)
		}
		publicLeg := resolvedPublicLeg{
			isSpl:       leg.IsSpl,
			isDeposit:   leg.IsDeposit,
			amount:      leg.Amount,
			userAccount: userAccount,
		}
		if leg.IsSpl {
			poolAccount, err := parse.Hex32(leg.PoolAccount)
			if err != nil {
				return nil, fmt.Errorf("public_legs[%d].pool_account: %w", position, err)
			}
			publicLeg.poolAccount = poolAccount
		} else if leg.PoolAccount != "" {
			return nil, fmt.Errorf("public_legs[%d].pool_account must be empty for SOL", position)
		}
		resolved = append(resolved, publicLeg)
	}
	return resolved, nil
}

func externalDataFieldHash(data externalDataPreimage) *big.Int {
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], data.ExpiryUnixTs)
	legSection := []byte{byte(len(data.PublicLegs))}
	for _, leg := range data.PublicLegs {
		tag := byte(0)
		if leg.isSpl {
			tag = 1
		}
		legSection = append(legSection, tag)
		direction := byte(0)
		if leg.isDeposit {
			direction = 1
		}
		legSection = append(legSection, direction)
		var amount [8]byte
		binary.BigEndian.PutUint64(amount[:], leg.amount)
		legSection = append(legSection, amount[:]...)
		legSection = append(legSection, leg.userAccount[:]...)
		if leg.isSpl {
			legSection = append(legSection, leg.poolAccount[:]...)
		}
	}
	var outputSection []byte
	outputSection = binary.BigEndian.AppendUint16(outputSection, uint16(len(data.Outputs)))
	for _, output := range data.Outputs {
		outputSection = append(outputSection, output.utxoHash[:]...)
		outputSection = append(outputSection, output.ownerTag[:]...)
		if !output.hasData {
			outputSection = append(outputSection, 0)
			continue
		}
		outputSection = append(outputSection, 1)
		outputSection = binary.BigEndian.AppendUint16(outputSection, uint16(len(output.data)))
		outputSection = append(outputSection, output.data...)
	}
	var messageSection []byte
	messageSection = binary.BigEndian.AppendUint16(messageSection, uint16(len(data.Messages)))
	for _, message := range data.Messages {
		messageSection = append(messageSection, message.viewTag[:]...)
		messageSection = binary.BigEndian.AppendUint16(messageSection, uint16(len(message.data)))
		messageSection = append(messageSection, message.data...)
	}
	// Field order must match the canonical Rust ExternalDataHash byte-for-byte.
	// expiry_unix_ts is bound ONLY here, not in private_tx_hash: SPP can't
	// recompute private_tx_hash (it covers private input hashes), so this hash is
	// what lets SPP confirm the expiry it clock-checks is the one the owner
	// signed.
	return protocol.Sha256BEField(
		[]byte{data.InstructionDiscriminator},
		expiry[:],
		legSection,
		data.DataHash[:],
		data.ZoneDataHash[:],
		outputSection,
		messageSection,
	)
}
