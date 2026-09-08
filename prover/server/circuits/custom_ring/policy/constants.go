// Fixes circuit capacities and policy encodings for consistent rule
// selection, amount checks and commitment hashes.

package policy

import (
	"math/big"
	"math/bits"
)

// Fixed capacities bound the transaction slots, policy rows and shared facts in
// one proof.
const (
	NInputs       = 5
	NOutputs      = 4
	NRules        = 16
	NListFacts    = 10
	NInlineAssets = 8
	NSources      = 8
)

// PolicyVersion is committed in policy_hash.
const PolicyVersion = 4

// Subjects select the transaction value checked against a rule.
const (
	SubjectOutputOwner     = 1
	SubjectSender          = 2
	SubjectExitDestination = 3 // Rejected for enabled rules.
	SubjectAsset           = 4
)

// Modes select active list membership or absence at the supplied roots.
const (
	ModePresent = 1
	ModeAbsent  = 2
)

// Entry states distinguish active membership from a stored revocation.
const (
	EntryStateActive  = 1
	EntryStateCleared = 2
)

// Guard tags select no exemption, a subject threshold or an owner-and-asset
// limit.
const (
	GuardAlways             = 0
	GuardAboveAmount        = 1
	GuardAboveAmountByAsset = 2
)

// Absence uses an unclaimed address or an unspent cleared entry.
const (
	AbsentBranchUnclaimedAddress = 1
	AbsentBranchCleared          = 2
)

// Domain tags separate entry addresses, entry records and policy commitments.
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

// Entry UTXOs use the empty ring commitment Poseidon(0, 0).
var emptyRingHash = solAssetField

// UTXO amounts and thresholds use the same unsigned width.
const amountBits = 64

// Sum width includes the largest possible output group.
var amountSumBits = amountBits + bits.Len(uint(NOutputs-1))

// Adding the offset makes the top bit indicate total <= threshold.
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

// packedASCII encodes short domain tags as big endian fields without modular
// reduction.
func packedASCII(tag string) *big.Int {
	if len(tag) > 31 {
		panic("policy domain tag exceeds 31 bytes")
	}
	return new(big.Int).SetBytes([]byte(tag))
}
