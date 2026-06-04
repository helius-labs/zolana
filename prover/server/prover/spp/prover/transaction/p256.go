package transaction

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"light/light-prover/prover/spp/internal/p256key"
	"light/light-prover/prover/spp/parse"

	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

func p256WitnessForTransaction(
	tx ProofTransactionRequest,
	privateTxHash *big.Int,
	requiresP256 bool,
	allowMissingSignature bool,
) (gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], gnarkecdsa.Signature[emulated.P256Fr], error) {
	msg, err := parse.FieldBytes(privateTxHash)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, fmt.Errorf("private_tx_hash: %w", err)
	}
	if !requiresP256 && strings.TrimSpace(tx.P256OwnerPubkey) == "" {
		return inactiveP256Witness(msg[:])
	}
	if allowMissingSignature && (strings.TrimSpace(tx.P256OwnerPubkey) == "" || tx.P256SignatureR == "" || tx.P256SignatureS == "") {
		return inactiveP256Witness(msg[:])
	}

	pub, err := p256PubkeyWitness(tx.P256OwnerPubkey)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, fmt.Errorf("p256_owner_pubkey: %w", err)
	}
	if tx.P256SignatureR == "" || tx.P256SignatureS == "" {
		if requiresP256 {
			return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, fmt.Errorf("p256_signature_r and p256_signature_s are required for P256 inputs")
		}
		return inactiveP256Witness(msg[:])
	}

	r, err := parse.P256Scalar(tx.P256SignatureR)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, fmt.Errorf("p256_signature_r: %w", err)
	}
	s, err := parse.P256Scalar(tx.P256SignatureS)
	if err != nil {
		return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{}, gnarkecdsa.Signature[emulated.P256Fr]{}, fmt.Errorf("p256_signature_s: %w", err)
	}
	return pub, gnarkecdsa.Signature[emulated.P256Fr]{
		R: emulated.ValueOf[emulated.P256Fr](r),
		S: emulated.ValueOf[emulated.P256Fr](s),
	}, nil
}

func p256PubkeyWitness(compressedHex string) (gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], error) {
	compressed, err := parse.HexBytes(compressedHex)
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

func inactiveP256Witness(msg []byte) (gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], gnarkecdsa.Signature[emulated.P256Fr], error) {
	priv, err := p256key.PrivateKeyFromScalar(big.NewInt(7))
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
