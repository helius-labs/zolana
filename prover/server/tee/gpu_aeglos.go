//go:build aeglos

package tee

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

// nvmlAttester collects confidential computing evidence from every GPU the
// prover can reach and has NRAS judge it.
type nvmlAttester struct {
	mu   sync.Mutex
	arch string
	nras *nras
}

func newGPUAttester() (gpuAttester, error) {
	if ret := nvml.Init(); ret != nvml.SUCCESS {
		return nil, fmt.Errorf("NVML init: %s", nvml.ErrorString(ret))
	}
	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS || count == 0 {
		return nil, errors.New("NVML finds no GPU")
	}
	arch, err := deviceArch(count)
	if err != nil {
		return nil, err
	}
	return &nvmlAttester{arch: arch, nras: newNRAS()}, nil
}

func (a *nvmlAttester) attest(ctx context.Context, nonce [32]byte) ([]byte, error) {
	evidence, err := a.collect(nonce)
	if err != nil {
		return nil, err
	}
	return a.nras.attest(ctx, a.arch, nonce, evidence)
}

func (a *nvmlAttester) collect(nonce [32]byte) ([]gpuEvidence, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Evidence from a GPU outside CC mode, or with devtools on, proves nothing
	// about the confidentiality of the data copied to it.
	state, ret := nvml.SystemGetConfComputeState()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("NVML CC state: %s", nvml.ErrorString(ret))
	}
	if state.CcFeature != nvml.CC_SYSTEM_FEATURE_ENABLED || state.DevToolsMode != nvml.CC_SYSTEM_DEVTOOLS_MODE_OFF {
		return nil, errors.New("GPU confidential computing is off or in devtools mode")
	}
	ready, ret := nvml.SystemGetConfComputeGpusReadyState()
	if ret != nvml.SUCCESS || ready != nvml.CC_ACCEPTING_CLIENT_REQUESTS_TRUE {
		return nil, errors.New("GPUs do not accept confidential work")
	}
	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("NVML device count: %s", nvml.ErrorString(ret))
	}
	evidence := make([]gpuEvidence, 0, count)
	for i := range count {
		device, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("NVML device %d: %s", i, nvml.ErrorString(ret))
		}
		report := nvml.ConfComputeGpuAttestationReport{Nonce: nonce}
		if ret := device.GetConfComputeGpuAttestationReport(&report); ret != nvml.SUCCESS {
			return nil, fmt.Errorf("GPU %d attestation report: %s", i, nvml.ErrorString(ret))
		}
		certificate, ret := device.GetConfComputeGpuCertificate()
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("GPU %d certificate: %s", i, nvml.ErrorString(ret))
		}
		if report.AttestationReportSize > uint32(len(report.AttestationReport)) ||
			certificate.AttestationCertChainSize > uint32(len(certificate.AttestationCertChain)) {
			return nil, fmt.Errorf("GPU %d returned an oversized report", i)
		}
		evidence = append(evidence, gpuEvidence{
			Evidence:    base64.StdEncoding.EncodeToString(report.AttestationReport[:report.AttestationReportSize]),
			Certificate: base64.StdEncoding.EncodeToString(certificate.AttestationCertChain[:certificate.AttestationCertChainSize]),
		})
	}
	return evidence, nil
}

func deviceArch(count int) (string, error) {
	var arch string
	for i := range count {
		device, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return "", fmt.Errorf("NVML device %d: %s", i, nvml.ErrorString(ret))
		}
		value, ret := device.GetArchitecture()
		if ret != nvml.SUCCESS {
			return "", fmt.Errorf("NVML device %d architecture: %s", i, nvml.ErrorString(ret))
		}
		var name string
		switch value {
		case nvml.DEVICE_ARCH_HOPPER:
			name = "HOPPER"
		case nvml.DEVICE_ARCH_BLACKWELL:
			name = "BLACKWELL"
		default:
			return "", fmt.Errorf("GPU %d architecture %d has no NRAS support", i, value)
		}
		if arch != "" && arch != name {
			return "", errors.New("mixed GPU architectures")
		}
		arch = name
	}
	return arch, nil
}
