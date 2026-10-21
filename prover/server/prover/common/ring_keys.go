package common

import (
	"fmt"
	"strings"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/policy"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
)

// RingFamily is mirrored by RingCircuit in custom-rings/interface/src/key_catalog.rs.
type RingFamily int

const (
	RingPackedAudit RingFamily = iota
	RingDeliveredAudit
	RingAnonymousAudit
	RingAnonymousEntryAudit
	RingMemberPolicy
	RingDelegatePolicy
	RingApplyRecords
	RingRegisterKey
	RingDeposit
	RingAnonymousMerge
)

type RingKey struct {
	Circuit CircuitType
	Family  RingFamily
	// Inputs counts the input slots, queued writes or merged UTXOs the key sizes.
	Inputs  int
	Outputs int
}

// RingKeys takes each shape from the package that sizes it, one delegate key per SPP ring-authority key.
var RingKeys = ringKeys()

var ringKeysByCircuit = func() map[CircuitType]RingKey {
	keys := make(map[CircuitType]RingKey, len(RingKeys))
	for _, key := range RingKeys {
		keys[key.Circuit] = key
	}
	return keys
}()

func RingKeyOf(circuit CircuitType) (RingKey, bool) {
	key, ok := ringKeysByCircuit[circuit]
	return key, ok
}

// RingKeyFile names a custom-ring circuit's key file, or "" for none.
func RingKeyFile(c CircuitType) string {
	if !c.IsRing() {
		return ""
	}
	return strings.ReplaceAll(string(c), "-", "_") + ".key"
}

// CustomRingMergeAnonymousCircuitType names the anonymous merge disclosure circuit of one width.
func CustomRingMergeAnonymousCircuitType(width int) CircuitType {
	return RingKey{Family: RingAnonymousMerge, Inputs: width}.circuitType()
}

// MergeAnonymousWidths mirrors ANONYMOUS_MERGE_WIDTHS in custom-rings/interface/src/merge.rs.
var MergeAnonymousWidths = []int{8, 24}

func ringKeys() []RingKey {
	var keys []RingKey
	add := func(family RingFamily, inputs, outputs int) {
		key := RingKey{Family: family, Inputs: inputs, Outputs: outputs}
		key.Circuit = key.circuitType()
		keys = append(keys, key)
	}
	for _, outputs := range base.PackedAuditCapacities {
		add(RingPackedAudit, 0, outputs)
	}
	for _, outputs := range base.DeliveredAuditCapacities {
		add(RingDeliveredAudit, 0, outputs)
	}
	for _, shape := range base.AnonymousAuditShapes {
		add(RingAnonymousAudit, shape.InputClass, shape.Outputs)
	}
	for _, shape := range base.AnonymousEntryShapes {
		add(RingAnonymousEntryAudit, shape.InputClass, shape.Outputs)
	}
	for _, outputs := range policy.MemberOutputs {
		add(RingMemberPolicy, 0, outputs)
	}
	for _, shape := range RingAuthorityShapes {
		add(RingDelegatePolicy, shape.NInputs, shape.NOutputs)
	}
	for _, writes := range registry.ApplyWidths {
		add(RingApplyRecords, writes, 0)
	}
	add(RingRegisterKey, 0, 0)
	add(RingDeposit, 0, 0)
	for _, width := range MergeAnonymousWidths {
		add(RingAnonymousMerge, width, 0)
	}
	return keys
}

func (k RingKey) circuitType() CircuitType {
	named := func(format string, args ...any) CircuitType {
		return CircuitType("custom-ring-" + fmt.Sprintf(format, args...))
	}
	switch k.Family {
	case RingPackedAudit:
		return named("audit-packed-%d", k.Outputs)
	case RingDeliveredAudit:
		return named("audit-delivered-%d", k.Outputs)
	case RingAnonymousAudit:
		return named("audit-anonymous-%d-%d", k.Inputs, k.Outputs)
	case RingAnonymousEntryAudit:
		return named("audit-anonymous-entry-%d-%d", k.Inputs, k.Outputs)
	case RingMemberPolicy:
		return named("policy-member-%d", k.Outputs)
	case RingDelegatePolicy:
		return named("policy-delegate-%dx%d", k.Inputs, k.Outputs)
	case RingApplyRecords:
		return named("apply-records-%d", k.Inputs)
	case RingRegisterKey:
		return CustomRingKeyRegisterCircuitType
	case RingDeposit:
		return CustomRingDepositCircuitType
	case RingAnonymousMerge:
		return named("merge-anonymous-%d", k.Inputs)
	}
	panic(fmt.Sprintf("common: unknown ring family %d", k.Family))
}
