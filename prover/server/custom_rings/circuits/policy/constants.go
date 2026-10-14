package policy

import (
	"math/big"
	"math/bits"
)

// Capacities of one proof.
const (
	NInputs         = 5
	NOutputs        = 4
	NRules          = 16
	NListFacts      = 10
	NInlineAssets   = 8
	NSources        = 8
	NVelocityAssets = 8
)

// PolicyVersion is committed in policy_hash.
const PolicyVersion = 7

// Subjects select the transaction value a rule checks, SubjectExitDestination is rejected.
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

// Guards waive a rule at or below a subject threshold or an owner and asset limit.
const (
	GuardAlways             = 0
	GuardAboveAmount        = 1
	GuardAboveAmountByAsset = 2
)

// Absence is an unclaimed address or an unspent cleared entry.
const (
	AbsentBranchUnclaimedAddress = 1
	AbsentBranchCleared          = 2
)

var (
	policyAddressDomain = packedASCII("zolana:ring-policy:address:v1")
	policyRecordDomain  = packedASCII("zolana:ring-policy:record:v1")
	policyTableDomain   = packedASCII("zolana:ring-policy:policy:v1")
	SpendAddressDomain  = packedASCII("zolana:ring-policy:spend:v1")
	SpendRecordDomain   = packedASCII("zolana:ring-spend:record:v1")
)

// solAssetField is Poseidon(0, 0), the asset of policy entries and spend records.
var solAssetField, _ = new(big.Int).SetString("2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864", 16)

const amountBits = 64

// The sum width bounds the larger slot group, the offset's top bit marks total <= threshold.
var (
	amountSumBits   = amountBits + bits.Len(uint(max(NInputs, NOutputs)-1))
	amountSumOffset = new(big.Int).Lsh(big.NewInt(1), uint(amountSumBits))
)

// packedASCII reads a tag of at most 31 bytes as a big-endian field.
func packedASCII(tag string) *big.Int {
	if len(tag) > 31 {
		panic("policy domain tag exceeds 31 bytes")
	}
	return new(big.Int).SetBytes([]byte(tag))
}
