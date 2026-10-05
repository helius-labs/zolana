package tee

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testdata is shared with the Rust and TypeScript clients.
const testdata = "../../tee/testdata"

// probeFixture holds a real dstack-nvidia-0.5.9 attestation.
type probeFixture struct {
	CapturedAt  int64       `json:"captured_at"`
	Attestation Attestation `json:"attestation"`
}

func loadProbeFixture(t *testing.T) probeFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(testdata, "probe_attestation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture probeFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

// TestCaptureProbeFixture rewrites probe_attestation.json with live PCCS collateral.
func TestCaptureProbeFixture(t *testing.T) {
	source := os.Getenv("ZOLANA_TEE_CAPTURE")
	if source == "" {
		t.Skip("set ZOLANA_TEE_CAPTURE to a Phala attestation response to recapture")
	}
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	var phala struct {
		AppCertificates []struct {
			Quote string `json:"quote"`
		} `json:"app_certificates"`
		TCBInfo struct {
			EventLog json.RawMessage `json:"event_log"`
		} `json:"tcb_info"`
	}
	if err := json.Unmarshal(raw, &phala); err != nil {
		t.Fatal(err)
	}
	if len(phala.AppCertificates) == 0 || phala.AppCertificates[0].Quote == "" {
		t.Fatal("attestation response carries no quote")
	}
	quote, err := hex.DecodeString(phala.AppCertificates[0].Quote)
	if err != nil {
		t.Fatal(err)
	}
	collateral, err := newCollateralSource(DefaultPCCSURL).forQuote(context.Background(), quote)
	if err != nil {
		t.Fatal(err)
	}
	fixture := probeFixture{
		CapturedAt: time.Now().Unix(),
		Attestation: Attestation{
			Quote:         phala.AppCertificates[0].Quote,
			EventLog:      phala.TCBInfo.EventLog,
			Collateral:    collateral,
			HPKEPublicKey: hex.EncodeToString(make([]byte, 32)),
		},
	}
	out, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(testdata, "probe_attestation.json"), append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
