package p256

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/consensys/gnark/constraint"
)

type (
	AgreeKeyCircuit      = agreeKeyCircuit
	SelfAgreementCircuit = selfAgreementCircuit
)

var (
	Compile         = compile
	SolveAgreement  = solveAgreement
	AgreeKeyWitness = agreeKeyWitness
)

func CheckSelfAgreement(t *testing.T, cs constraint.ConstraintSystem, name string, scalar *big.Int) {
	t.Helper()
	row := scalarRow{name: name, scalar: scalar, reduced: new(big.Int).Mod(scalar, elliptic.P256().Params().N)}
	row.check(t, cs, row.selfAgreementWitness(t))
}
