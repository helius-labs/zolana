package common

import (
	"path/filepath"
	"testing"
)

func TestLazyKeyManagerBuildsTransferKeyPaths(t *testing.T) {
	keysDir := filepath.Join("tmp", "proving-keys")
	manager := NewLazyKeyManager(keysDir, &DownloadConfig{})

	tests := map[string]string{
		"transfer ring eddsa": manager.determineTransferKeyPath(TransferRingCircuitType, 2, 3),
		"transfer ring p256":  manager.determineTransferKeyPath(TransferP256RingCircuitType, 2, 3),
	}

	expected := map[string]string{
		// Key filenames mirror the verifying-key modules.
		"transfer ring eddsa": filepath.Join(keysDir, "transfer_ring_2_3.key"),
		"transfer ring p256":  filepath.Join(keysDir, "transfer_p256_ring_2_3.key"),
	}

	for name, got := range tests {
		if got != expected[name] {
			t.Fatalf("%s path mismatch: got %q, want %q", name, got, expected[name])
		}
	}
}

func TestLazyKeyManagerBuildsDirectSpendKeyPaths(t *testing.T) {
	keysDir := filepath.Join("tmp", "proving-keys")
	manager := NewLazyKeyManager(keysDir, &DownloadConfig{})

	for _, test := range []struct {
		kind     CircuitType
		inputs   uint32
		outputs  uint32
		filename string
	}{
		{InputCertificateCircuitType, 36, 0, "input-certificate_36_0.key"},
		{NullifierFreshnessCircuitType, 36, 0, "nullifier-freshness_36_0.key"},
		{SpendBalanceCircuitType, 16, 2, "spend-balance_16_2.key"},
		{DirectPaymentCircuitType, 512, 2, "direct-payment_512_2.key"},
		{DirectPaymentGKRCircuitType, 144, 2, "direct-payment-gkr_144_2.key"},
		{DirectPaymentGKRCircuitType, 512, 2, "direct-payment-gkr_512_2.key"},
		{DirectPaymentAdmittedCircuitType, 144, 2, "direct-payment-admitted_144_2.key"},
		{DirectPaymentAdmittedCircuitType, 512, 2, "direct-payment-admitted_512_2.key"},
	} {
		got := manager.determineTransferKeyPath(test.kind, test.inputs, test.outputs)
		want := filepath.Join(keysDir, test.filename)
		if got != want {
			t.Fatalf("%s path mismatch: got %q, want %q", test.kind, got, want)
		}
	}
}

func TestLazyKeyManagerBuildsCustomRingKeyPaths(t *testing.T) {
	keysDir := filepath.Join("tmp", "proving-keys")
	manager := NewLazyKeyManager(keysDir, &DownloadConfig{})

	tests := map[CircuitType]string{
		CustomRingBaseCircuitType:   CustomRingBaseKeyFile,
		CustomRingPolicyCircuitType: CustomRingPolicyKeyFile,
	}
	for circuitType, filename := range tests {
		got := manager.determineRingKeyPath(circuitType)
		want := filepath.Join(keysDir, filename)
		if got != want {
			t.Fatalf("%s path mismatch: got %q, want %q", circuitType, got, want)
		}
	}
}
