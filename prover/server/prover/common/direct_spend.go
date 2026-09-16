package common

const (
	InputCertificateCircuitType   CircuitType = "input-certificate"
	NullifierFreshnessCircuitType CircuitType = "nullifier-freshness"
	SpendBalanceCircuitType       CircuitType = "spend-balance"
	DirectPaymentCircuitType      CircuitType = "direct-payment"
)

func IsDirectSpend(kind CircuitType) bool {
	switch kind {
	case InputCertificateCircuitType, NullifierFreshnessCircuitType, SpendBalanceCircuitType, DirectPaymentCircuitType:
		return true
	default:
		return false
	}
}

func IsDirectSpendShape(kind CircuitType, inputs, outputs uint32) bool {
	switch kind {
	case InputCertificateCircuitType, NullifierFreshnessCircuitType:
		return (inputs == 8 || inputs == 36 || inputs == 128 || inputs == 512) && outputs == 0
	case SpendBalanceCircuitType:
		return (inputs == 1 || inputs == 4 || inputs == 16) && (outputs == 1 || outputs == 2)
	case DirectPaymentCircuitType:
		return (inputs == 8 || inputs == 36 || inputs == 128 || inputs == 512) && (outputs == 1 || outputs == 2)
	default:
		return false
	}
}
