package transfer

import "math/big"

// Baked circuit widths, every slot beyond the claimed count is padding.
const (
	NIn           = 5
	NOut          = 4
	NRules        = 16
	NPool         = 10
	NInlineAssets = 8
)

// PolicyVersion enters the policy_hash preimage, mirroring
// ring_policy::POLICY_VERSION.
const PolicyVersion = 1

// What a rule ranges over, ExitDestination having no in-circuit instance.
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

// InlineKind marks a rule whose members are inlined in the table, never a
// record kind.
const InlineKind = 0

const (
	RecordStateActive  = 1
	RecordStateCleared = 2
)

// GuardAboveAmount exempts an instance at or below the rule's threshold.
const GuardAboveAmount = 1

const (
	AbsentBranchNoAddress = 1
	AbsentBranchCleared   = 2
)

// Domain separators, the ASCII tags right-aligned in 32 bytes and read
// big-endian, mirroring ring_policy::packed_ascii.
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

// solAssetField is Poseidon(0, 0), the native-SOL asset id of a record utxo,
// mirroring zolana_interface::SOL_ASSET_FIELD.
var solAssetField, _ = new(big.Int).SetString(
	"2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864", 16)

// emptyRingHash is Poseidon(0, 0) again, the ring hash of a utxo in no ring.
var emptyRingHash = solAssetField

var amountOffset = new(big.Int).Lsh(big.NewInt(1), 64)

// ruleShift are the field weights of the ring_policy::Rule::encoded byte groups.
var ruleShift = [4]*big.Int{
	new(big.Int).Lsh(big.NewInt(1), 8),
	new(big.Int).Lsh(big.NewInt(1), 16),
	new(big.Int).Lsh(big.NewInt(1), 24),
	new(big.Int).Lsh(big.NewInt(1), 32),
}

// packedASCII right-aligns the tag in 32 bytes, capped at 31 to stay below the
// field modulus.
func packedASCII(tag string) *big.Int {
	if len(tag) > 31 {
		panic("transfer: domain tag exceeds 31 bytes")
	}
	return new(big.Int).SetBytes([]byte(tag))
}
