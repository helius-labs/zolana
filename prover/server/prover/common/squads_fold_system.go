package common

import (
	"encoding/binary"
	"io"
	"zolana/prover/prover/gpuprove"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

// SquadsKeyEncryptionFoldProofSystem holds the keys and constraints for one
// key-encryption fold.
//
// Keyed by the per-leg recipient count and the leg count, because the inner
// verifying key is a compile-time constant of the outer circuit. One outer key
// names one inner circuit, so the zone binds a fold from its width alone.
type SquadsKeyEncryptionFoldProofSystem struct {
	KeysPerLeg       uint32
	Legs             uint32
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
	ConstraintSystem constraint.ConstraintSystem
}

// SquadsZoneFoldProofSystem holds the keys and constraints for one zone fold,
// keyed by the leg shape and the leg count.
type SquadsZoneFoldProofSystem struct {
	NInputs          uint32
	NOutputs         uint32
	Legs             uint32
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
	ConstraintSystem constraint.ConstraintSystem
}

func (ps *SquadsKeyEncryptionFoldProofSystem) WriteTo(w io.Writer) (int64, error) {
	return writeFoldSystem(w, []uint32{ps.KeysPerLeg, ps.Legs}, ps.ProvingKey, ps.VerifyingKey, ps.ConstraintSystem)
}

func (ps *SquadsKeyEncryptionFoldProofSystem) UnsafeReadFrom(r io.Reader) (int64, error) {
	header := []*uint32{&ps.KeysPerLeg, &ps.Legs}
	total, err := readFoldHeader(r, header)
	if err != nil {
		return total, err
	}
	read, err := readFoldKeys(r, &ps.ProvingKey, &ps.VerifyingKey, &ps.ConstraintSystem)
	return total + read, err
}

func (ps *SquadsZoneFoldProofSystem) WriteTo(w io.Writer) (int64, error) {
	return writeFoldSystem(w, []uint32{ps.NInputs, ps.NOutputs, ps.Legs}, ps.ProvingKey, ps.VerifyingKey, ps.ConstraintSystem)
}

func (ps *SquadsZoneFoldProofSystem) UnsafeReadFrom(r io.Reader) (int64, error) {
	header := []*uint32{&ps.NInputs, &ps.NOutputs, &ps.Legs}
	total, err := readFoldHeader(r, header)
	if err != nil {
		return total, err
	}
	read, err := readFoldKeys(r, &ps.ProvingKey, &ps.VerifyingKey, &ps.ConstraintSystem)
	return total + read, err
}

func writeFoldSystem(
	w io.Writer,
	header []uint32,
	pk groth16.ProvingKey,
	vk groth16.VerifyingKey,
	ccs constraint.ConstraintSystem,
) (int64, error) {
	var total int64
	var intBuf [4]byte
	for _, field := range header {
		binary.BigEndian.PutUint32(intBuf[:], field)
		written, err := w.Write(intBuf[:])
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

func readFoldHeader(r io.Reader, header []*uint32) (int64, error) {
	var total int64
	var intBuf [4]byte
	for _, field := range header {
		read, err := io.ReadFull(r, intBuf[:])
		total += int64(read)
		if err != nil {
			return total, err
		}
		*field = binary.BigEndian.Uint32(intBuf[:])
	}
	return total, nil
}

func readFoldKeys(
	r io.Reader,
	pk *groth16.ProvingKey,
	vk *groth16.VerifyingKey,
	ccs *constraint.ConstraintSystem,
) (int64, error) {
	var total int64

	*pk = gpuprove.NewProvingKey()
	read, err := (*pk).UnsafeReadFrom(r)
	total += read
	if err != nil {
		return total, err
	}

	*vk = groth16.NewVerifyingKey(ecc.BN254)
	read, err = (*vk).UnsafeReadFrom(r)
	total += read
	if err != nil {
		return total, err
	}

	*ccs = groth16.NewCS(ecc.BN254)
	read, err = (*ccs).ReadFrom(r)
	return total + read, err
}
