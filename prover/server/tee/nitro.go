package tee

import (
	"context"
	"crypto/hpke"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

type nsmSession interface {
	Send(request.Request) (response.Response, error)
}

type nitro struct {
	nsm nsmSession
}

type nitroEvidence struct {
	Document string `json:"document"`
}

// NewNitro attests from an AWS Nitro Enclave through the Nitro Secure Module at /dev/nsm.
func NewNitro() (Attester, error) {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("nitro secure module: %w", err)
	}
	return &nitro{nsm: session}, nil
}

func (n *nitro) platform() string { return "aws-nitro" }

func (n *nitro) hostsGPU() bool { return false }

func (n *nitro) key(context.Context) (hpke.PrivateKey, error) {
	kem, _, _ := suite()
	return kem.GenerateKey()
}

func (n *nitro) evidence(_ context.Context, in evidenceRequest) (any, error) {
	answer, err := n.nsm.Send(&request.Attestation{
		UserData:  in.reportData[:],
		Nonce:     in.nonce,
		PublicKey: in.publicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("NSM attestation: %w", err)
	}
	if answer.Error != "" {
		return nil, fmt.Errorf("NSM attestation: %s", answer.Error)
	}
	if answer.Attestation == nil || len(answer.Attestation.Document) == 0 {
		return nil, errors.New("NSM returned no attestation document")
	}
	return nitroEvidence{Document: hex.EncodeToString(answer.Attestation.Document)}, nil
}
