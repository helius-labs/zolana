package common

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

func FromHex(i *big.Int, s string) error {
	s = strings.TrimPrefix(s, "0x")
	_, ok := i.SetString(s, 16)
	if !ok {
		return fmt.Errorf("invalid number: %s", s)
	}
	return nil
}

func ToHex(i *big.Int) string {
	return fmt.Sprintf("0x%064x", i)
}

type ProofJSON struct {
	Ar                 [2]string    `json:"ar"`
	Bs                 [2][2]string `json:"bs"`
	Krs                [2]string    `json:"krs"`
	ProofCommitment    []string     `json:"proof_commitment,omitempty"`
	ProofCommitmentPok []string     `json:"proof_commitment_pok,omitempty"`
}

func (p *Proof) MarshalJSON() ([]byte, error) {
	const fpSize = 32
	var buf bytes.Buffer
	_, err := p.Proof.WriteRawTo(&buf)
	if err != nil {
		return nil, err
	}
	proofBytes := buf.Bytes()
	proofJson := ProofJSON{}
	proofHexNumbers := [8]string{}
	for i := 0; i < 8; i++ {
		proofHexNumbers[i] = ToHex(new(big.Int).SetBytes(proofBytes[i*fpSize : (i+1)*fpSize]))
	}

	proofJson.Ar = [2]string{proofHexNumbers[0], proofHexNumbers[1]}
	proofJson.Bs = [2][2]string{
		{proofHexNumbers[2], proofHexNumbers[3]},
		{proofHexNumbers[4], proofHexNumbers[5]},
	}
	proofJson.Krs = [2]string{proofHexNumbers[6], proofHexNumbers[7]}
	if proofBN, ok := p.Proof.(*groth16bn254.Proof); ok {
		if len(proofBN.Commitments) > 1 {
			return nil, fmt.Errorf("expected at most one BSB22 commitment, got %d", len(proofBN.Commitments))
		}
		if len(proofBN.Commitments) == 1 {
			commitment := proofBN.Commitments[0].RawBytes()
			proofJson.ProofCommitment = []string{
				ToHex(new(big.Int).SetBytes(commitment[:32])),
				ToHex(new(big.Int).SetBytes(commitment[32:])),
			}
			pok := proofBN.CommitmentPok.RawBytes()
			proofJson.ProofCommitmentPok = []string{
				ToHex(new(big.Int).SetBytes(pok[:32])),
				ToHex(new(big.Int).SetBytes(pok[32:])),
			}
		}
	}

	return json.Marshal(proofJson)
}

func (p *Proof) UnmarshalJSON(data []byte) error {
	var proofJson ProofJSON
	err := json.Unmarshal(data, &proofJson)
	if err != nil {
		return err
	}
	proofHexNumbers := [8]string{
		proofJson.Ar[0],
		proofJson.Ar[1],
		proofJson.Bs[0][0],
		proofJson.Bs[0][1],
		proofJson.Bs[1][0],
		proofJson.Bs[1][1],
		proofJson.Krs[0],
		proofJson.Krs[1],
	}
	proofInts := [8]big.Int{}
	for i := 0; i < 8; i++ {
		err = FromHex(&proofInts[i], proofHexNumbers[i])
		if err != nil {
			return err
		}
	}
	const fpSize = 32
	proofBytes := make([]byte, 8*fpSize)
	for i := 0; i < 8; i++ {
		intBytes := proofInts[i].Bytes()
		// Pad with leading zeros to ensure exactly 32 bytes
		if len(intBytes) <= fpSize {
			copy(proofBytes[i*fpSize+fpSize-len(intBytes):(i+1)*fpSize], intBytes)
		} else {
			// If somehow longer than 32 bytes, take the last 32 bytes
			copy(proofBytes[i*fpSize:(i+1)*fpSize], intBytes[len(intBytes)-fpSize:])
		}
	}

	p.Proof = groth16.NewProof(ecc.BN254)

	// For gnark v0.14 compatibility: proofs now include Commitments and CommitmentPok fields
	// We need to append empty commitment data to make ReadFrom work
	var fullProofBuf bytes.Buffer
	fullProofBuf.Write(proofBytes)

	tempProof := groth16.NewProof(ecc.BN254)
	var tempBuf bytes.Buffer
	tempProof.WriteRawTo(&tempBuf)
	expectedSize := tempBuf.Len()

	// If gnark expects more than 256 bytes, pad with zeros for commitment fields
	if expectedSize > len(proofBytes) {
		padding := make([]byte, expectedSize-len(proofBytes))
		fullProofBuf.Write(padding)
	}

	_, err = p.Proof.ReadFrom(bytes.NewReader(fullProofBuf.Bytes()))
	if err != nil {
		return err
	}
	return nil
}

func (ps *MerkleProofSystem) WriteTo(w io.Writer) (int64, error) {
	var totalWritten int64 = 0
	var intBuf [4]byte

	fieldsToWrite := []uint32{
		ps.InclusionTreeHeight,
		ps.InclusionNumberOfCompressedAccounts,
		ps.NonInclusionTreeHeight,
		ps.NonInclusionNumberOfCompressedAccounts,
	}

	for _, field := range fieldsToWrite {
		binary.BigEndian.PutUint32(intBuf[:], field)
		written, err := w.Write(intBuf[:])
		totalWritten += int64(written)
		if err != nil {
			return totalWritten, err
		}
	}

	keyWritten, err := ps.ProvingKey.WriteTo(w)
	totalWritten += keyWritten
	if err != nil {
		return totalWritten, err
	}

	keyWritten, err = ps.VerifyingKey.WriteTo(w)
	totalWritten += keyWritten
	if err != nil {
		return totalWritten, err
	}

	keyWritten, err = ps.ConstraintSystem.WriteTo(w)
	totalWritten += keyWritten
	if err != nil {
		return totalWritten, err
	}
	return totalWritten, nil
}

func (ps *MerkleProofSystem) UnsafeReadFrom(r io.Reader) (int64, error) {
	var totalRead int64 = 0
	var intBuf [4]byte

	fieldsToRead := []*uint32{
		&ps.InclusionTreeHeight,
		&ps.InclusionNumberOfCompressedAccounts,
		&ps.NonInclusionTreeHeight,
		&ps.NonInclusionNumberOfCompressedAccounts,
	}

	for _, field := range fieldsToRead {
		read, err := io.ReadFull(r, intBuf[:])
		totalRead += int64(read)
		if err != nil {
			return totalRead, err
		}
		*field = binary.BigEndian.Uint32(intBuf[:])
	}

	ps.ProvingKey = groth16.NewProvingKey(ecc.BN254)
	keyRead, err := ps.ProvingKey.UnsafeReadFrom(r)
	totalRead += keyRead
	if err != nil {
		return totalRead, err
	}

	ps.VerifyingKey = groth16.NewVerifyingKey(ecc.BN254)
	keyRead, err = ps.VerifyingKey.UnsafeReadFrom(r)
	totalRead += keyRead
	if err != nil {
		return totalRead, err
	}

	ps.ConstraintSystem = groth16.NewCS(ecc.BN254)
	keyRead, err = ps.ConstraintSystem.ReadFrom(r)
	totalRead += keyRead
	if err != nil {
		return totalRead, err
	}

	return totalRead, nil
}

func (ps *TransferProofSystem) WriteTo(w io.Writer) (int64, error) {
	var totalWritten int64 = 0
	var intBuf [4]byte

	requiresP256 := uint32(0)
	if ps.RequiresP256 {
		requiresP256 = 1
	}
	fieldsToWrite := []uint32{
		ps.NInputs,
		ps.NOutputs,
		requiresP256,
	}

	for _, field := range fieldsToWrite {
		binary.BigEndian.PutUint32(intBuf[:], field)
		written, err := w.Write(intBuf[:])
		totalWritten += int64(written)
		if err != nil {
			return totalWritten, err
		}
	}

	keyWritten, err := ps.ProvingKey.WriteTo(w)
	totalWritten += keyWritten
	if err != nil {
		return totalWritten, err
	}

	keyWritten, err = ps.VerifyingKey.WriteTo(w)
	totalWritten += keyWritten
	if err != nil {
		return totalWritten, err
	}

	keyWritten, err = ps.ConstraintSystem.WriteTo(w)
	totalWritten += keyWritten
	if err != nil {
		return totalWritten, err
	}

	return totalWritten, nil
}

func (ps *TransferProofSystem) UnsafeReadFrom(r io.Reader) (int64, error) {
	var totalRead int64 = 0
	var intBuf [4]byte

	var requiresP256 uint32
	fieldsToRead := []*uint32{
		&ps.NInputs,
		&ps.NOutputs,
		&requiresP256,
	}

	for _, field := range fieldsToRead {
		read, err := io.ReadFull(r, intBuf[:])
		totalRead += int64(read)
		if err != nil {
			return totalRead, err
		}
		*field = binary.BigEndian.Uint32(intBuf[:])
	}
	ps.RequiresP256 = requiresP256 != 0

	ps.ProvingKey = groth16.NewProvingKey(ecc.BN254)
	keyRead, err := ps.ProvingKey.UnsafeReadFrom(r)
	totalRead += keyRead
	if err != nil {
		return totalRead, err
	}

	ps.VerifyingKey = groth16.NewVerifyingKey(ecc.BN254)
	keyRead, err = ps.VerifyingKey.UnsafeReadFrom(r)
	totalRead += keyRead
	if err != nil {
		return totalRead, err
	}

	ps.ConstraintSystem = groth16.NewCS(ecc.BN254)
	keyRead, err = ps.ConstraintSystem.ReadFrom(r)
	totalRead += keyRead
	if err != nil {
		return totalRead, err
	}

	return totalRead, nil
}

func ReadSystemFromFile(path string) (interface{}, error) {
	if strings.Contains(strings.ToLower(path), "transfer") {
		ps := new(TransferProofSystem)
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		if _, err = ps.UnsafeReadFrom(file); err != nil {
			return nil, err
		}
		// Rail comes from the serialized RequiresP256 flag; the confidentiality mode
		// is not in the key header (kept stable so existing keys/VKs are untouched),
		// so it is read from the canonical file name (transfer_confidential_*.key /
		// transfer_p256_confidential_*.key).
		ps.Confidential = strings.Contains(strings.ToLower(path), "confidential")
		// Zone keys are named transfer_zone_*.key / transfer_p256_zone_*.key and
		// are anonymous-only (no confidential zone variant). The two forms per rail
		// are confidential (non-zone) and zone (anonymous).
		zone := strings.Contains(strings.ToLower(path), "zone")
		// Zone-authority keys are named transfer_zone_authority_*.key (Solana-only,
		// anonymous). Detect it before the plain "zone" case: the name contains both
		// "transfer" (matched this branch) and "zone".
		zoneAuthority := strings.Contains(strings.ToLower(path), "zone_authority")
		switch {
		case zoneAuthority:
			ps.CircuitType = TransferZoneAuthorityCircuitType
		case ps.RequiresP256 && zone:
			ps.CircuitType = TransferP256ZoneCircuitType
		case zone:
			ps.CircuitType = TransferZoneCircuitType
		case ps.RequiresP256:
			ps.CircuitType = TransferP256ConfidentialCircuitType
		default:
			ps.CircuitType = TransferConfidentialCircuitType
		}
		return ps, nil
	} else if strings.Contains(strings.ToLower(path), "merge") {
		// Merge reuses TransferProofSystem (generic Groth16 holder); the file name
		// (merge_8_1.key) carries no "transfer" substring, so it needs its own
		// branch or it would be misread as a MerkleProofSystem.
		ps := new(TransferProofSystem)
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		if _, err = ps.UnsafeReadFrom(file); err != nil {
			return nil, err
		}
		// merge_zone_8_1.key is the policy-zone variant; the default merge file is
		// merge_8_1.key.
		if strings.Contains(strings.ToLower(path), "zone") {
			ps.CircuitType = MergeZoneCircuitType
		} else {
			ps.CircuitType = MergeCircuitType
		}
		return ps, nil
	} else if strings.Contains(strings.ToLower(path), "address-append") {
		ps := new(BatchProofSystem)
		ps.CircuitType = BatchAddressAppendCircuitType
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		_, err = ps.UnsafeReadFrom(file)
		if err != nil {
			return nil, err
		}
		return ps, nil
	} else if strings.Contains(strings.ToLower(path), "append") {
		ps := new(BatchProofSystem)
		ps.CircuitType = BatchAppendCircuitType
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		_, err = ps.UnsafeReadFrom(file)
		if err != nil {
			return nil, err
		}
		return ps, nil
	} else if strings.Contains(strings.ToLower(path), "update") {
		ps := new(BatchProofSystem)
		ps.CircuitType = BatchUpdateCircuitType
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		_, err = ps.UnsafeReadFrom(file)
		if err != nil {
			return nil, err
		}
		return ps, nil
	} else {
		ps := new(MerkleProofSystem)
		filename := strings.ToLower(filepath.Base(path))
		if strings.HasPrefix(filename, "v2_") {
			ps.Version = 2
		} else if strings.HasPrefix(filename, "v1_") {
			ps.Version = 1
		} else if strings.Contains(filename, "mainnet") {
			ps.Version = 1
		} else {
			ps.Version = 1
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		_, err = ps.UnsafeReadFrom(file)
		if err != nil {
			return nil, err
		}
		return ps, nil
	}
}

func (ps *BatchProofSystem) WriteTo(w io.Writer) (int64, error) {
	var totalWritten int64 = 0
	var intBuf [4]byte

	fieldsToWrite := []uint32{
		ps.TreeHeight,
		ps.BatchSize,
	}

	for _, field := range fieldsToWrite {
		binary.BigEndian.PutUint32(intBuf[:], field)
		written, err := w.Write(intBuf[:])
		totalWritten += int64(written)
		if err != nil {
			return totalWritten, err
		}
	}

	keyWritten, err := ps.ProvingKey.WriteTo(w)
	totalWritten += keyWritten
	if err != nil {
		return totalWritten, err
	}

	keyWritten, err = ps.VerifyingKey.WriteTo(w)
	totalWritten += keyWritten
	if err != nil {
		return totalWritten, err
	}

	keyWritten, err = ps.ConstraintSystem.WriteTo(w)
	totalWritten += keyWritten
	if err != nil {
		return totalWritten, err
	}

	return totalWritten, nil
}

func (ps *BatchProofSystem) UnsafeReadFrom(r io.Reader) (int64, error) {
	var totalRead int64 = 0
	var intBuf [4]byte

	fieldsToRead := []*uint32{
		&ps.TreeHeight,
		&ps.BatchSize,
	}

	for _, field := range fieldsToRead {
		read, err := io.ReadFull(r, intBuf[:])
		totalRead += int64(read)
		if err != nil {
			return totalRead, err
		}
		*field = binary.BigEndian.Uint32(intBuf[:])
	}

	ps.ProvingKey = groth16.NewProvingKey(ecc.BN254)
	keyRead, err := ps.ProvingKey.UnsafeReadFrom(r)
	totalRead += keyRead
	if err != nil {
		return totalRead, err
	}

	ps.VerifyingKey = groth16.NewVerifyingKey(ecc.BN254)
	keyRead, err = ps.VerifyingKey.UnsafeReadFrom(r)
	totalRead += keyRead
	if err != nil {
		return totalRead, err
	}

	ps.ConstraintSystem = groth16.NewCS(ecc.BN254)
	keyRead, err = ps.ConstraintSystem.ReadFrom(r)
	totalRead += keyRead
	if err != nil {
		return totalRead, err
	}

	return totalRead, nil
}
