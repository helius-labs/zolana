package common

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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
	ProofCommitment    []string     `json:"proofCommitment,omitempty"`
	ProofCommitmentPok []string     `json:"proofCommitmentPok,omitempty"`
	// ProvingKeySha256 is 64 lowercase hex digits, omitted when the proof
	// system was not loaded from a key file.
	ProvingKeySha256 string `json:"provingKeySha256,omitempty"`
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
	if p.ProvingKeySha256 != ([32]byte{}) {
		proofJson.ProvingKeySha256 = hex.EncodeToString(p.ProvingKeySha256[:])
	}

	return json.Marshal(proofJson)
}

func (p *Proof) UnmarshalJSON(data []byte) error {
	var proofJson ProofJSON
	if err := json.Unmarshal(data, &proofJson); err != nil {
		return err
	}
	proofHexNumbers := []string{
		proofJson.Ar[0],
		proofJson.Ar[1],
		proofJson.Bs[0][0],
		proofJson.Bs[0][1],
		proofJson.Bs[1][0],
		proofJson.Bs[1][1],
		proofJson.Krs[0],
		proofJson.Krs[1],
	}

	hasCommitment := len(proofJson.ProofCommitment) != 0
	hasCommitmentPok := len(proofJson.ProofCommitmentPok) != 0
	if hasCommitment != hasCommitmentPok {
		return fmt.Errorf("proof_commitment and proof_commitment_pok must both be present")
	}
	if hasCommitment {
		if len(proofJson.ProofCommitment) != 2 {
			return fmt.Errorf("proof_commitment must contain exactly 2 coordinates, got %d", len(proofJson.ProofCommitment))
		}
		if len(proofJson.ProofCommitmentPok) != 2 {
			return fmt.Errorf("proof_commitment_pok must contain exactly 2 coordinates, got %d", len(proofJson.ProofCommitmentPok))
		}
	}

	const fpSize = 32
	appendCoordinates := func(dst []byte, coordinates []string) ([]byte, error) {
		for _, coordinate := range coordinates {
			var value big.Int
			if err := FromHex(&value, coordinate); err != nil {
				return nil, err
			}
			fieldBytes := make([]byte, fpSize)
			intBytes := value.Bytes()
			if len(intBytes) > fpSize {
				intBytes = intBytes[len(intBytes)-fpSize:]
			}
			copy(fieldBytes[fpSize-len(intBytes):], intBytes)
			dst = append(dst, fieldBytes...)
		}
		return dst, nil
	}

	proofBytes, err := appendCoordinates(nil, proofHexNumbers)
	if err != nil {
		return err
	}

	var commitmentCount [4]byte
	if hasCommitment {
		binary.BigEndian.PutUint32(commitmentCount[:], 1)
	}
	proofBytes = append(proofBytes, commitmentCount[:]...)

	if hasCommitment {
		proofBytes, err = appendCoordinates(proofBytes, proofJson.ProofCommitment)
		if err != nil {
			return err
		}
		proofBytes, err = appendCoordinates(proofBytes, proofJson.ProofCommitmentPok)
		if err != nil {
			return err
		}
	} else {
		// gnark always serializes CommitmentPok, even when there are no commitments.
		proofBytes = append(proofBytes, make([]byte, 2*fpSize)...)
	}

	p.Proof = groth16.NewProof(ecc.BN254)
	if _, err := p.Proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return err
	}
	// Copied back so a proof stored in and reread from the Redis queue keeps
	// the key digest.
	p.ProvingKeySha256 = [32]byte{}
	if proofJson.ProvingKeySha256 != "" {
		digest, err := hex.DecodeString(proofJson.ProvingKeySha256)
		if err != nil || len(digest) != len(p.ProvingKeySha256) {
			return fmt.Errorf("provingKeySha256 must be 64 hex digits")
		}
		copy(p.ProvingKeySha256[:], digest)
	}
	return nil
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

func (ps *RingProofSystem) WriteTo(w io.Writer) (int64, error) {
	var total int64

	written, err := ps.ProvingKey.WriteTo(w)
	total += written
	if err != nil {
		return total, err
	}
	written, err = ps.VerifyingKey.WriteTo(w)
	total += written
	if err != nil {
		return total, err
	}
	written, err = ps.ConstraintSystem.WriteTo(w)
	total += written
	return total, err
}

func (ps *RingProofSystem) UnsafeReadFrom(r io.Reader) (int64, error) {
	var total int64
	ps.ProvingKey = groth16.NewProvingKey(ecc.BN254)
	read, err := ps.ProvingKey.UnsafeReadFrom(r)
	total += read
	if err != nil {
		return total, err
	}
	ps.VerifyingKey = groth16.NewVerifyingKey(ecc.BN254)
	read, err = ps.VerifyingKey.UnsafeReadFrom(r)
	total += read
	if err != nil {
		return total, err
	}
	ps.ConstraintSystem = groth16.NewCS(ecc.BN254)
	read, err = ps.ConstraintSystem.ReadFrom(r)
	total += read
	return total, err
}

// readKeyFile deserializes the key file at path through read and hashes every
// byte on the way, so the reported digest is of the bytes actually loaded, for
// lockfile and local keys alike. Bytes the deserializer leaves unread are hashed
// too: the digest always covers the whole file, as proving-keys.lock does. For a
// pinned key this is a second hash on top of EnsureProvingKey's lockfile check,
// paid once per key per process.
func readKeyFile(path string, read func(io.Reader) (int64, error)) ([32]byte, error) {
	var digest [32]byte
	file, err := os.Open(path)
	if err != nil {
		return digest, err
	}
	defer file.Close()

	hasher := sha256.New()
	reader := io.TeeReader(file, hasher)
	if _, err := read(reader); err != nil {
		return digest, err
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return digest, err
	}
	copy(digest[:], hasher.Sum(nil))
	return digest, nil
}

func ReadSystemFromFile(path string) (interface{}, error) {
	lowerPath := strings.ToLower(path)
	if circuitType, ok := ringCircuitOfKeyFile(filepath.Base(lowerPath)); ok {
		ps := &RingProofSystem{
			CircuitType: circuitType,
		}
		digest, err := readKeyFile(path, ps.UnsafeReadFrom)
		if err != nil {
			return nil, err
		}
		ps.ProvingKeySha256 = digest
		return ps, nil
	} else if strings.Contains(lowerPath, "transfer") {
		ps := new(TransferProofSystem)
		digest, err := readKeyFile(path, ps.UnsafeReadFrom)
		if err != nil {
			return nil, err
		}
		ps.ProvingKeySha256 = digest
		// Transfer variants are resolved from canonical key filenames. The
		// RequiresP256 header is retained as a consistency check for P256 keys.
		ring := strings.Contains(strings.ToLower(path), "ring")
		p256Ring := strings.Contains(strings.ToLower(path), "p256_ring")
		// Ring-authority keys are named transfer_ring_authority_*.key (Solana-only,
		// anonymous). Detect it before the plain "ring" case: the name contains both
		// "transfer" (matched this branch) and "ring".
		ringAuthority := strings.Contains(strings.ToLower(path), "ring_authority")
		switch {
		case ringAuthority:
			ps.CircuitType = TransferRingAuthorityCircuitType
		case p256Ring:
			ps.CircuitType = TransferP256RingCircuitType
		case ring:
			ps.CircuitType = TransferRingCircuitType
		default:
			ps.CircuitType = TransferConfidentialCircuitType
		}
		ps.Confidential = !ringAuthority
		return ps, nil
	} else if strings.Contains(strings.ToLower(path), "merge") {
		// Merge reuses TransferProofSystem (generic Groth16 holder); the file name
		// (merge_8_1.key) carries no "transfer" substring, so it needs its own
		// branch or it would fall through to the unrecognized-file error.
		ps := new(TransferProofSystem)
		digest, err := readKeyFile(path, ps.UnsafeReadFrom)
		if err != nil {
			return nil, err
		}
		ps.ProvingKeySha256 = digest
		// merge_ring_8_1.key is the policy-ring variant; the default merge file is
		// merge_8_1.key.
		if strings.Contains(strings.ToLower(path), "ring") {
			ps.CircuitType = MergeRingCircuitType
		} else {
			ps.CircuitType = MergeCircuitType
		}
		return ps, nil
	} else if strings.Contains(strings.ToLower(path), "address-append") {
		ps := new(BatchProofSystem)
		ps.CircuitType = BatchAddressAppendCircuitType
		digest, err := readKeyFile(path, ps.UnsafeReadFrom)
		if err != nil {
			return nil, err
		}
		ps.ProvingKeySha256 = digest
		return ps, nil
	} else {
		return nil, fmt.Errorf("unrecognized proving key file: %s", path)
	}
}

func ringCircuitOfKeyFile(name string) (CircuitType, bool) {
	for circuitType, file := range RingKeyFiles {
		if file == name {
			return circuitType, true
		}
	}
	return "", false
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
