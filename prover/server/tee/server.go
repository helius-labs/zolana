package tee

import (
	"context"
	"crypto/hpke"
	"fmt"
)

// Attester has unexported methods, so only package tee adds a platform.
type Attester interface {
	platform() string
	hostsGPU() bool
	key(ctx context.Context) (hpke.PrivateKey, error)
	evidence(ctx context.Context, in evidenceRequest) (any, error)
}

type evidenceRequest struct {
	nonce      []byte
	reportData [64]byte
	publicKey  []byte
}

type Config struct {
	Attester Attester
	// UsesGPU makes every attestation carry NRAS verified GPU evidence.
	UsesGPU bool
}

type Server struct {
	key       hpke.PrivateKey
	publicKey []byte
	attester  Attester
	gpu       gpuAttester
	permits   chan struct{}
}

// gpuAttester returns the raw NRAS response for evidence collected with nonce,
// after checking it inside the TEE.
type gpuAttester interface {
	attest(ctx context.Context, nonce [32]byte) ([]byte, error)
}

// maxEncryptedBody caps an encrypted request above the largest forester batch.
const maxEncryptedBody = 64<<20 + gcmTagSize

// attestationConcurrency bounds concurrent evidence requests to the platform.
const attestationConcurrency = 4

func New(ctx context.Context, config Config) (*Server, error) {
	attester := config.Attester
	if config.UsesGPU && !attester.hostsGPU() {
		return nil, fmt.Errorf("%s attests no GPU, run the prover on the CPU backend", attester.platform())
	}
	key, err := attester.key(ctx)
	if err != nil {
		return nil, err
	}
	var gpu gpuAttester
	if config.UsesGPU {
		if gpu, err = newGPUAttester(); err != nil {
			return nil, err
		}
	}
	return &Server{
		key:       key,
		publicKey: key.PublicKey().Bytes(),
		attester:  attester,
		gpu:       gpu,
		permits:   make(chan struct{}, attestationConcurrency),
	}, nil
}

func (s *Server) PublicKey() []byte { return s.publicKey }
