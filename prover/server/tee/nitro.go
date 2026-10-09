package tee

import (
	"context"
	"crypto/hpke"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

// Measured with the image.
const (
	keySourcePath = "/etc/zolana-nitro/key-source"
	kmsKeyPath    = "/etc/zolana-nitro/kms-key"
)

type nsmSession interface {
	Send(request.Request) (response.Response, error)
}

type nitro struct {
	nsm     nsmSession
	release *kmsRelease
}

type nitroEvidence struct {
	Document string `json:"document"`
}

// NewNitro attests from an AWS Nitro Enclave through the Nitro Secure Module at /dev/nsm.
func NewNitro() (Attester, error) {
	source, err := os.ReadFile(keySourcePath)
	if err != nil {
		return nil, fmt.Errorf("nitro key source: %w", err)
	}
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("nitro secure module: %w", err)
	}
	return newNitro(session, string(source), func() ([]byte, error) { return os.ReadFile(kmsKeyPath) })
}

func newNitro(session nsmSession, keySource string, kmsKey func() ([]byte, error)) (*nitro, error) {
	switch strings.TrimSpace(keySource) {
	case "boot":
		return &nitro{nsm: session}, nil
	case "kms":
		keyARN, err := kmsKey()
		if err != nil {
			return nil, fmt.Errorf("nitro KMS key: %w", err)
		}
		release, err := newKMSRelease(strings.TrimSpace(string(keyARN)))
		if err != nil {
			return nil, err
		}
		return &nitro{nsm: session, release: release}, nil
	default:
		return nil, fmt.Errorf("nitro key source %q is neither kms nor boot", keySource)
	}
}

func (n *nitro) platform() string { return "aws-nitro" }

func (n *nitro) hostsGPU() bool { return false }

func (n *nitro) key(ctx context.Context) (hpke.PrivateKey, error) {
	if n.release == nil {
		kem, _, _ := suite()
		return kem.GenerateKey()
	}
	seed, err := n.release.seed(ctx, n.attest)
	if err != nil {
		return nil, fmt.Errorf("KMS key release: %w", err)
	}
	defer clear(seed)
	return deriveKey(seed)
}

func (n *nitro) evidence(_ context.Context, in evidenceRequest) (any, error) {
	document, err := n.attest(&request.Attestation{
		UserData:  in.reportData[:],
		Nonce:     in.nonce,
		PublicKey: in.publicKey,
	})
	if err != nil {
		return nil, err
	}
	return nitroEvidence{Document: hex.EncodeToString(document)}, nil
}

func (n *nitro) attest(r *request.Attestation) ([]byte, error) {
	answer, err := n.nsm.Send(r)
	if err != nil {
		return nil, fmt.Errorf("NSM attestation: %w", err)
	}
	if answer.Error != "" {
		return nil, fmt.Errorf("NSM attestation: %s", answer.Error)
	}
	if answer.Attestation == nil || len(answer.Attestation.Document) == 0 {
		return nil, errors.New("NSM returned no attestation document")
	}
	return answer.Attestation.Document, nil
}
