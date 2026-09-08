package policy

import (
	"math/big"
	"math/bits"
)

const (
	NIn           = 5
	NOut          = 4
	NRules        = 16
	NAnswers      = 10
	NInlineAssets = 8
	NSources      = 8
)

// PolicyVersion is committed in policy_hash.
const PolicyVersion = 4

// ExitDestination is reserved and rejected.
const (
	SubjectOutputOwner     = 1
	SubjectSender          = 2
	SubjectExitDestination = 3
	SubjectAsset           = 4
)

const (
	ModePresent = 1
	ModeAbsent  = 2
)

const (
	EntryStateActive  = 1
	EntryStateCleared = 2
)

const (
	GuardAlways             = 0
	GuardAboveAmount        = 1
	GuardAboveAmountByAsset = 2
)

const (
	AbsentBranchNeverCreated = 1
	AbsentBranchCleared      = 2
)

// Domain tags use big endian field encoding.
const (
	addressDomainTag = "zolana:ring-policy:address:v1"
	recordDomainTag  = "zolana:ring-policy:record:v1"
	tableDomainTag   = "zolana:ring-policy:policy:v1"
)

var (
	policyAddressDomain = packedASCII(addressDomainTag)
	policyRecordDomain  = packedASCII(recordDomainTag)
	policyTableDomain   = packedASCII(tableDomainTag)
)

// Policy entries use the SOL asset Poseidon(0, 0).
var solAssetField, _ = new(big.Int).SetString(
	"2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864", 16)

var emptyRingHash = solAssetField

const amountBits = 64

var amountSumBits = amountBits + bits.Len(uint(NOut-1))
var amountSumOffset = new(big.Int).Lsh(big.NewInt(1), uint(amountSumBits))

// Packed rows bind each field at its encoded byte offset.
var ruleWeights = struct {
	mode, listMask, guardTag, threshold, altListMask *big.Int
}{
	mode:        new(big.Int).Lsh(big.NewInt(1), 8),
	listMask:    new(big.Int).Lsh(big.NewInt(1), 16),
	guardTag:    new(big.Int).Lsh(big.NewInt(1), 24),
	threshold:   new(big.Int).Lsh(big.NewInt(1), 32),
	altListMask: new(big.Int).Lsh(big.NewInt(1), 96),
}

// Tags fit below the field modulus.
func packedASCII(tag string) *big.Int {
	if len(tag) > 31 {
		panic("policy domain tag exceeds 31 bytes")
	}
	return new(big.Int).SetBytes([]byte(tag))
}
