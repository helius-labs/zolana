package policy

import (
	"math/big"
	"math/bits"
)

// Capacities of one proof.
const (
	NInputs        = 5
	NOutputs       = 4
	NRules         = 16
	NAmountGuards  = 8
	NSources       = 8
	NOutflowLimits = 8
	// NSubjects opens input owners, output owners, then output assets.
	NSubjects = NInputs + 2*NOutputs
	// NForeign is the number of curator registries a policy may read lists from.
	NForeign = 1
)

// PolicyVersion is committed in policy_hash.
const PolicyVersion = 10

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

// Guards waive a rule at or below a subject threshold or an owner and asset limit.
const (
	GuardAlways             = 0
	GuardAboveAmount        = 1
	GuardAboveAmountByAsset = 2
)

var policyTableDomain = packedASCII("zolana:ring-policy:policy:v1")

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
