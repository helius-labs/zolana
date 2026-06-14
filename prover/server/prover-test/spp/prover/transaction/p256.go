package transaction

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	txcircuit "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover-test/spp/internal/p256key"
	"zolana/prover/prover-test/spp/parse"

	"github.com/consensys/gnark/std/math/emulated"
)

func p256WitnessForTransaction(
	tx ProofTransactionRequest,
	msg [32]byte,
	requiresP256 bool,
	allowMissingSignature bool,
) (txcircuit.P256PublicKey, txcircuit.P256Signature, error) {
	if !requiresP256 && strings.TrimSpace(tx.P256OwnerPubkey) == "" {
		return unusedP256Witness(msg[:])
	}
	if allowMissingSignature && (strings.TrimSpace(tx.P256OwnerPubkey) == "" || tx.P256SignatureR == "" || tx.P256SignatureS == "") {
		return unusedP256Witness(msg[:])
	}

	pub, err := p256PubkeyWitness(tx.P256OwnerPubkey)
	if err != nil {
		return txcircuit.P256PublicKey{}, txcircuit.P256Signature{}, fmt.Errorf("p256_owner_pubkey: %w", err)
	}
	if tx.P256SignatureR == "" || tx.P256SignatureS == "" {
		if requiresP256 {
			return txcircuit.P256PublicKey{}, txcircuit.P256Signature{}, fmt.Errorf("p256_signature_r and p256_signature_s are required for P256 inputs")
		}
		return unusedP256Witness(msg[:])
	}

	r, err := parse.P256Scalar(tx.P256SignatureR)
	if err != nil {
		return txcircuit.P256PublicKey{}, txcircuit.P256Signature{}, fmt.Errorf("p256_signature_r: %w", err)
	}
	s, err := parse.P256Scalar(tx.P256SignatureS)
	if err != nil {
		return txcircuit.P256PublicKey{}, txcircuit.P256Signature{}, fmt.Errorf("p256_signature_s: %w", err)
	}
	return pub, txcircuit.P256Signature{
		R: emulated.ValueOf[emulated.P256Fr](r),
		S: emulated.ValueOf[emulated.P256Fr](s),
	}, nil
}

func p256PubkeyWitness(compressedHex string) (txcircuit.P256PublicKey, error) {
	compressed, err := parse.HexBytes(compressedHex)
	if err != nil {
		return txcircuit.P256PublicKey{}, err
	}
	if len(compressed) != 33 {
		return txcircuit.P256PublicKey{}, fmt.Errorf("expected 33-byte compressed P256 public key, got %d", len(compressed))
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil || y == nil {
		return txcircuit.P256PublicKey{}, fmt.Errorf("invalid compressed P256 public key")
	}
	return txcircuit.P256PublicKey{
		X: emulated.ValueOf[emulated.P256Fp](x),
		Y: emulated.ValueOf[emulated.P256Fp](y),
	}, nil
}

func unusedP256Witness(msg []byte) (txcircuit.P256PublicKey, txcircuit.P256Signature, error) {
	priv, err := p256key.PrivateKeyFromScalar(big.NewInt(7))
	if err != nil {
		return txcircuit.P256PublicKey{}, txcircuit.P256Signature{}, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
	if err != nil {
		return txcircuit.P256PublicKey{}, txcircuit.P256Signature{}, err
	}
	return txcircuit.P256PublicKey{
			X: emulated.ValueOf[emulated.P256Fp](priv.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](priv.PublicKey.Y),
		}, txcircuit.P256Signature{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		}, nil
}
