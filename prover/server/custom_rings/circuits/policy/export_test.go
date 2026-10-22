package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

var (
	ComparisonHint = comparisonHint
	RulePartsHint  = rulePartsHint
)

var DecodeTable = Table.decode

func BindMemberStatement(api frontend.API, c *MemberPolicyCircuit) {
	bindStatement(api, c.PublicInputHash, c.Statement())
}

func BindDelegateStatement(api frontend.API, c *DelegatePolicyCircuit) {
	bindStatement(api, c.PublicInputHash, c.Statement())
}

func KeyStatement(api frontend.API, c *KeyRegisterCircuit, nullifierPk frontend.Variable, sealed base.Sealed) []frontend.Variable {
	return c.statement(api, nullifierPk, sealed)
}
