package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"

	"zolana/prover/prover/common"
	"zolana/prover/prover/provingkeys"
)

func main() {
	keyPath := flag.String("key", "", "Pinned combined proving key")
	publicInput := flag.String("public-input", "", "Expected public input hash")
	flag.Parse()
	if err := verify(*keyPath, *publicInput, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(`{"verified":true}`)
}

func verify(keyPath, publicInput string, input io.Reader) error {
	value, ok := new(big.Int).SetString(publicInput, 0)
	if !ok || value.Sign() < 0 || value.Cmp(ecc.BN254.ScalarField()) >= 0 {
		return errors.New("invalid public input field")
	}
	manifest, err := provingkeys.Load()
	if err != nil {
		return err
	}
	entry, ok := manifest.Keys[filepath.Base(keyPath)]
	if !ok {
		return errors.New("key is absent from pinned manifest")
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	// 1. Only authenticated key bytes may enter unchecked point decoding.
	if int64(len(data)) != entry.Size || hex.EncodeToString(digest[:]) != entry.Sha256 {
		return errors.New("key does not match pinned manifest")
	}
	var vk groth16.VerifyingKey
	switch filepath.Base(keyPath) {
	case common.CustomRingBaseKeyFile, common.CustomRingPolicyKeyFile:
		var system common.RingProofSystem
		if _, err = system.UnsafeReadFrom(bytes.NewReader(data)); err != nil {
			return err
		}
		vk = system.VerifyingKey
	default:
		var system common.TransferProofSystem
		if _, err = system.UnsafeReadFrom(bytes.NewReader(data)); err != nil {
			return err
		}
		vk = system.VerifyingKey
	}
	encoded, err := io.ReadAll(io.LimitReader(input, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(encoded) > 1<<20 {
		return errors.New("proof response exceeds size limit")
	}
	var wire common.ProofJSON
	if err = json.Unmarshal(encoded, &wire); err != nil {
		return err
	}
	// 2. Proof coordinates must remain canonical before point decoding.
	for _, coordinates := range [][]string{wire.Ar[:], wire.Bs[0][:], wire.Bs[1][:], wire.Krs[:], wire.ProofCommitment, wire.ProofCommitmentPok} {
		for _, coordinate := range coordinates {
			var value big.Int
			if err = common.FromHex(&value, coordinate); err != nil || value.Sign() < 0 || value.Cmp(fp.Modulus()) >= 0 {
				return errors.New("invalid proof coordinate field")
			}
		}
	}
	var proof common.Proof
	if err = json.Unmarshal(encoded, &proof); err != nil {
		return err
	}
	public, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	values := make(chan any, 1)
	values <- value
	close(values)
	if err = public.Fill(1, 0, values); err != nil {
		return err
	}
	return groth16.Verify(proof.Proof, vk, public)
}
