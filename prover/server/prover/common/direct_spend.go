package common

const (
	InputCertificateCircuitType           CircuitType = "input-certificate"
	NullifierFreshnessCircuitType         CircuitType = "nullifier-freshness"
	SpendBalanceCircuitType               CircuitType = "spend-balance"
	DirectPaymentCircuitType              CircuitType = "direct-payment"
	DirectPaymentGKRCircuitType           CircuitType = "direct-payment-gkr"
	DirectPaymentAdmittedCircuitType      CircuitType = "direct-payment-admitted"
	DirectPaymentAdmittedDAG10CircuitType CircuitType = "direct-payment-admitted-dag10"
)

func IsDirectSpend(kind CircuitType) bool {
	switch kind {
	case InputCertificateCircuitType, NullifierFreshnessCircuitType, SpendBalanceCircuitType, DirectPaymentCircuitType, DirectPaymentGKRCircuitType, DirectPaymentAdmittedCircuitType, DirectPaymentAdmittedDAG10CircuitType:
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
	case DirectPaymentGKRCircuitType:
		// 100x1 is the inline shape: statement, proof and commitment fit one
		// transaction, so a 100-note spend settles without a buffer account.
		return ((inputs == 144 || inputs == 512) && outputs == 2) || (inputs == 100 && outputs == 1)
	case DirectPaymentAdmittedCircuitType:
		return (inputs == 144 || inputs == 512) && outputs == 2
	case DirectPaymentAdmittedDAG10CircuitType:
		return inputs == 512 && outputs == 2
	default:
		return false
	}
}
