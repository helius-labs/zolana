package policy

// Table capacities, mirrored by custom-rings/policy/src/rule_table.rs.
const (
	NRules         = 16
	NInlineAssets  = 8
	NSources       = 8
	NOutflowLimits = 8
)

// Policy table hash layout, mirrored by EncodedRuleTable::hash in custom-rings/policy/src/rule_table.rs.
const (
	// PolicyTableVersion enters the table hash, every layout change bumps it.
	PolicyTableVersion = 11
	PolicyTableFields  = 2 + 2*NSources + 3 + NRules + 2*NInlineAssets + 3*NOutflowLimits
	// PolicyTableRate fields join the accumulator per Poseidon call, twelve inputs is the syscall maximum.
	PolicyTableRate = 11
)

// Every table hash call absorbs a full rate of fields.
const _ = uint(-(PolicyTableFields % PolicyTableRate))

// Rule row values, mirrored by Subject, Mode and the guard tags of Rule::encoded in custom-rings/policy/src/rule_table.rs.
const (
	SubjectOutputOwner = 1
	SubjectSender      = 2
	SubjectAsset       = 4

	ModePresent = 1
	ModeAbsent  = 2

	GuardAlways             = 0
	GuardAboveAmount        = 1
	GuardAboveAmountByAsset = 2
)

// MemberOutputs are the member key capacities, every output opens its own owner and asset entry.
var MemberOutputs = [...]int{2, 4, 8, 16}
