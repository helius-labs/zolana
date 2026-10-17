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
	"github.com/consensys/gnark/constraint"
)

func FromHex(i *big.Int, s string) error {
	s = strings.TrimPrefix(s, "0x")
	_, ok := i.SetString(s, 16)
	if !ok {
		return fmt.Errorf("invalid number")
	}
	return nil
}

func ToHex(i *big.Int) string {
	return fmt.Sprintf("0x%064x", i)
}

type ProofJSON struct {
	Resolution         *ProofResolution `json:"resolution,omitempty"`
	Ar                 [2]string        `json:"ar"`
	Bs                 [2][2]string     `json:"bs"`
	Krs                [2]string        `json:"krs"`
	ProofCommitment    []string         `json:"proofCommitment,omitempty"`
	ProofCommitmentPok []string         `json:"proofCommitmentPok,omitempty"`
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
	proofJson := ProofJSON{Resolution: p.Resolution}
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
	p.Resolution = proofJson.Resolution
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
	hasCommitment := uint32(0)
	if ps.HasCommitment {
		hasCommitment = 1
	}
	return writeSystem(w, []uint32{ps.NInputs, ps.NOutputs, hasCommitment}, ps.ProvingKey, ps.VerifyingKey, ps.ConstraintSystem)
}

func (ps *TransferProofSystem) UnsafeReadFrom(r io.Reader) (int64, error) {
	var hasCommitment uint32
	read, err := readSystem(r, []*uint32{&ps.NInputs, &ps.NOutputs, &hasCommitment}, &ps.ProvingKey, &ps.VerifyingKey, &ps.ConstraintSystem)
	ps.HasCommitment = hasCommitment != 0
	return read, err
}

func (ps *RingProofSystem) WriteTo(w io.Writer) (int64, error) {
	return writeSystem(w, nil, ps.ProvingKey, ps.VerifyingKey, ps.ConstraintSystem)
}

func (ps *RingProofSystem) UnsafeReadFrom(r io.Reader) (int64, error) {
	return readSystem(r, nil, &ps.ProvingKey, &ps.VerifyingKey, &ps.ConstraintSystem)
}

func (ps *BatchProofSystem) WriteTo(w io.Writer) (int64, error) {
	return writeSystem(w, []uint32{ps.TreeHeight, ps.BatchSize}, ps.ProvingKey, ps.VerifyingKey, ps.ConstraintSystem)
}

func (ps *BatchProofSystem) UnsafeReadFrom(r io.Reader) (int64, error) {
	return readSystem(r, []*uint32{&ps.TreeHeight, &ps.BatchSize}, &ps.ProvingKey, &ps.VerifyingKey, &ps.ConstraintSystem)
}

// writeSystem writes the key file layout, big-endian header words then the keys and the circuit.
func writeSystem(w io.Writer, header []uint32, pk groth16.ProvingKey, vk groth16.VerifyingKey, ccs constraint.ConstraintSystem) (int64, error) {
	var total int64
	for _, field := range header {
		written, err := w.Write(binary.BigEndian.AppendUint32(nil, field))
		total += int64(written)
		if err != nil {
			return total, err
		}
	}
	for _, part := range []io.WriterTo{pk, vk, ccs} {
		written, err := part.WriteTo(w)
		total += written
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func readSystem(r io.Reader, header []*uint32, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, ccs *constraint.ConstraintSystem) (int64, error) {
	var total int64
	var word [4]byte
	for _, field := range header {
		read, err := io.ReadFull(r, word[:])
		total += int64(read)
		if err != nil {
			return total, err
		}
		*field = binary.BigEndian.Uint32(word[:])
	}
	*pk, *vk, *ccs = groth16.NewProvingKey(ecc.BN254), groth16.NewVerifyingKey(ecc.BN254), groth16.NewCS(ecc.BN254)
	for _, part := range []func(io.Reader) (int64, error){(*pk).UnsafeReadFrom, (*vk).UnsafeReadFrom, (*ccs).ReadFrom} {
		read, err := part(r)
		total += read
		if err != nil {
			return total, err
		}
	}
	return total, nil
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
	// Classify by file name only, a parent directory name must not pick the rail.
	name := strings.ToLower(filepath.Base(path))
	if strings.Contains(name, "p256") {
		return nil, fmt.Errorf("unsupported proving key %q", filepath.Base(path))
	}
	if circuitType, ok := ringCircuitOfKeyFile(name); ok {
		ps := &RingProofSystem{
			CircuitType: circuitType,
		}
		digest, err := readKeyFile(path, ps.UnsafeReadFrom)
		if err != nil {
			return nil, err
		}
		ps.ProvingKeySha256 = digest
		return ps, nil
	} else if strings.Contains(name, "transfer") {
		ps := new(TransferProofSystem)
		digest, err := readKeyFile(path, ps.UnsafeReadFrom)
		if err != nil {
			return nil, err
		}
		ps.ProvingKeySha256 = digest
		// Transfer variants are resolved from canonical key filenames. The
		// HasCommitment header is retained as a consistency check for P256 keys.
		ring := strings.Contains(name, "ring")
		ed25519Ring := strings.Contains(name, "ed25519_ring")
		// Ring-authority keys are named transfer_ring_authority_*.key (Solana-only,
		// anonymous). Detect it before the plain "ring" case: the name contains both
		// "transfer" (matched this branch) and "ring".
		ringAuthority := strings.Contains(name, "ring_authority")
		switch {
		case ringAuthority:
			ps.CircuitType = TransferRingAuthorityCircuitType
		case ed25519Ring:
			ps.CircuitType = TransferAnonymousRingEd25519CircuitType
		case ring:
			ps.CircuitType = TransferRingCircuitType
		default:
			ps.CircuitType = TransferConfidentialCircuitType
		}
		ps.Confidential = !ringAuthority
		return ps, nil
	} else if strings.Contains(name, "merge") {
		// Merge reuses TransferProofSystem (generic Groth16 holder); the file name
		// (merge_24_1.key) carries no "transfer" substring, so it needs its own
		// branch or it would fall through to the unrecognized-file error.
		ps := new(TransferProofSystem)
		digest, err := readKeyFile(path, ps.UnsafeReadFrom)
		if err != nil {
			return nil, err
		}
		ps.ProvingKeySha256 = digest
		// merge_ring_24_1.key is the policy-ring variant; the default merge file is
		// merge_24_1.key.
		if strings.Contains(name, "ring") {
			ps.CircuitType = MergeRingCircuitType
		} else {
			ps.CircuitType = MergeCircuitType
		}
		return ps, nil
	} else if strings.Contains(name, "address-append") {
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
	for _, circuit := range RingCircuitTypes {
		if RingKeyFile(circuit) == name {
			return circuit, true
		}
	}
	return "", false
}
