package tee

import (
	"context"
	"crypto/hpke"
	"fmt"
	"os"
)

const DefaultSocket = "/var/run/dstack.sock"

type Config struct {
	Socket  string
	PCCSURL string
	// UsesGPU makes every attestation carry NRAS verified GPU evidence.
	UsesGPU bool
}

type Server struct {
	key        hpke.PrivateKey
	publicKey  []byte
	guest      *guest
	collateral *collateralSource
	gpu        gpuAttester
	permits    chan struct{}
}

// gpuAttester returns the raw NRAS response for evidence collected with nonce,
// after checking it inside the TEE.
type gpuAttester interface {
	attest(ctx context.Context, nonce [32]byte) ([]byte, error)
}

// maxSealedBody caps a sealed request above the largest forester batch.
const maxSealedBody = 64<<20 + gcmTagSize

// attestationConcurrency bounds concurrent quote requests to the guest agent.
const attestationConcurrency = 4

func New(ctx context.Context, config Config) (*Server, error) {
	if _, err := os.Stat(config.Socket); err != nil {
		return nil, fmt.Errorf("dstack guest agent socket: %w", err)
	}
	g := newGuest(config.Socket)
	secret, err := g.key(ctx, keyPath)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(secret)
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
		key:        key,
		publicKey:  key.PublicKey().Bytes(),
		guest:      g,
		collateral: newCollateralSource(config.PCCSURL),
		gpu:        gpu,
		permits:    make(chan struct{}, attestationConcurrency),
	}, nil
}

// deriveKey runs RFC 9180 DeriveKeyPair on the KMS secret, so every replica
// of the app serves the key pinned in client releases.
func deriveKey(secret []byte) (hpke.PrivateKey, error) {
	kem, _, _ := suite()
	return kem.DeriveKeyPair(secret)
}

func (s *Server) PublicKey() []byte { return s.publicKey }
