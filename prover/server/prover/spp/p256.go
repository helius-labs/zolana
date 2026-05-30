package spp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

func p256WitnessForTransaction(
	tx ProofTransactionRequest,
	privateTxHash *big.Int,
	requiresP256 bool,
	allowMissingSignature bool,
) (gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], gnarkecdsa.Signature[emulated.P256Fr], error) {
	msg := proofFieldBytes(privateTxHash)
	if !requiresP256 && strings.TrimSpace(tx.P256SignerPubkey) == "" {
		return dummyP256Witness(msg[:])
	}
	if allowMissingSignature && (strings.TrimSpace(tx.P256SignerPubkey) == "" || tx.P256SignatureR == "" || tx.P256SignatureS == "") {
		return dummyP256Witness(msg[:])
	}
	pub, err := p256PubkeyWitness(tx.P256SignerPubkey)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, fmt.Errorf("p256_signer_pubkey: %w", err)
	}
	if tx.P256SignatureR == "" || tx.P256SignatureS == "" {
		if requiresP256 {
			return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, fmt.Errorf("p256_signature_r and p256_signature_s are required for P256 inputs")
		}
		return dummyP256Witness(msg[:])
	}
	r, err := parseP256Scalar(tx.P256SignatureR)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, fmt.Errorf("p256_signature_r: %w", err)
	}
	s, err := parseP256Scalar(tx.P256SignatureS)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, fmt.Errorf("p256_signature_s: %w", err)
	}
	return pub, gnarkecdsa.Signature[emulated.P256Fr]{
		R: emulated.ValueOf[emulated.P256Fr](r),
		S: emulated.ValueOf[emulated.P256Fr](s),
	}, nil
}

func p256PubkeyWitness(compressedHex string) (gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], error) {
	compressed, err := parseHexBytes(compressedHex)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, err
	}
	if len(compressed) != 33 {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, fmt.Errorf("expected 33-byte compressed P256 public key, got %d", len(compressed))
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil || y == nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, fmt.Errorf("invalid compressed P256 public key")
	}
	return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
		X: emulated.ValueOf[emulated.P256Fp](x),
		Y: emulated.ValueOf[emulated.P256Fp](y),
	}, nil
}

func dummyP256Witness(msg []byte) (gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], gnarkecdsa.Signature[emulated.P256Fr], error) {
	priv, err := fixedP256PrivateKey(big.NewInt(7))
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, err
	}
	return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](priv.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](priv.PublicKey.Y),
		}, gnarkecdsa.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		}, nil
}

func fixedP256PrivateKey(d *big.Int) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P256()
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, fmt.Errorf("invalid P256 private scalar")
	}
	x, y := curve.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}, nil
}

func parseP256Scalar(value string) (*big.Int, error) {
	parsed, err := parseBigInt(value)
	if err != nil {
		return nil, err
	}
	if parsed.Sign() <= 0 || parsed.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, fmt.Errorf("scalar is outside P256 scalar field")
	}
	return parsed, nil
}
