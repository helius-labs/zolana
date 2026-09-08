package policy

import (
	"math/big"
	"testing"
)

func TestRejectsMalformedCommittedPolicies(t *testing.T) {
	tests := []struct {
		name   string
		change func(*statement)
	}{
		{"reserved subject", func(s *statement) { s.rules[0].subject = SubjectExitDestination }},
		{"unknown subject", func(s *statement) { s.rules[0].subject = 255 }},
		{"unknown guard", func(s *statement) { s.rules[0].guardTag = 255 }},
		{"overlapping alternatives", func(s *statement) { s.rules[0].altMask = listMask(listAllow) }},
		{"alternative beside absent primary", func(s *statement) {
			s.rules[0].mode = ModeAbsent
			s.rules[0].mask = listMask(listBlock)
			s.rules[0].altMask = listMask(listAllow)
		}},
		{"unconfigured alternative", func(s *statement) { s.rules[0].altMask = listMask(8) }},
		{"nonpositional source", func(s *statement) { s.sources[7] = source{listId: 4, owner: big.NewInt(7)} }},
		{"empty source with owner", func(s *statement) { s.sources[7] = source{listId: 0, owner: big.NewInt(7)} }},
		{"configured source without owner", func(s *statement) { s.sources[7] = source{listId: 8, owner: big.NewInt(0)} }},
		{"zero scalar threshold", func(s *statement) { s.rules[0].guardTag = GuardAboveAmount }},
		{"threshold without guard", func(s *statement) { s.rules[0].threshold = 1 }},
		{"threshold beside per-asset guard", func(s *statement) {
			s.rules[0].guardTag = GuardAboveAmountByAsset
			s.rules[0].threshold = 1
			s.inlineLimits = []uint64{2000}
		}},
		{"sender guard", func(s *statement) {
			s.rules[1].guardTag = GuardAboveAmount
			s.rules[1].threshold = 2000
		}},
		{"owner threshold without enforced asset", func(s *statement) {
			s.rules[2].guardTag = GuardAboveAmount
			s.rules[2].threshold = 2000
		}},
		{"owner threshold with several assets", func(s *statement) {
			s.inlineAssets = append(s.inlineAssets, big.NewInt(17))
		}},
		{"per-asset guard on asset subject", func(s *statement) {
			s.rules[3].subject = SubjectAsset
			s.rules[3].guardTag = GuardAboveAmountByAsset
			s.rules[3].threshold = 0
			s.inlineLimits = []uint64{2000}
		}},
		{"duplicate assets under per-asset guard", func(s *statement) {
			s.rules[3].guardTag = GuardAboveAmountByAsset
			s.rules[3].threshold = 0
			s.inlineAssets = append(s.inlineAssets, s.inlineAssets[0])
			s.inlineLimits = []uint64{1000, 1000}
		}},
		{"zero limit with covering answer", func(s *statement) {
			s.rules[0].guardTag = GuardAboveAmountByAsset
			s.inlineLimits = []uint64{0}
		}},
		{"zero active inline asset", func(s *statement) {
			s.rules = nil
			s.inlineAssets = []*big.Int{big.NewInt(0)}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := newStatement(t, defaultFixture())
			test.change(s)
			rejectAssignment(t, s.assignment(t, []int{allowedActive, senderNotFrozen, blockedCleared}))
		})
	}
}

func TestUnconfiguredAssetFailsDespiteCoveringAnswer(t *testing.T) {
	s := newStatement(t, defaultFixture())
	s.rules = []rule{{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listAllow), guardTag: GuardAboveAmountByAsset}}
	s.inlineAssets = []*big.Int{big.NewInt(17)}
	s.inlineLimits = []uint64{2000}
	rejectAssignment(t, s.assignment(t, []int{allowedActive}))
}

func TestDisabledRulesHaveNoPolicyRequirements(t *testing.T) {
	s := newStatement(t, defaultFixture())
	c := s.assignment(t, []int{allowedActive, senderNotFrozen})
	c.Rules[NRules-1] = rule{subject: SubjectExitDestination, mode: 0, mask: listMask(8), guardTag: 255, threshold: 12}.wires()
	solve(t, testConstraintSystem(t), c)
}
