package common

import (
	"encoding/binary"
	"io"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

// NullifierFoldProofSystem holds the keys and constraints for one
// nullifier_fold outer circuit.
//
// Keyed by tree height, inner batch size, and run length, because the inner
// verifying key is a compile-time constant of the outer circuit. One outer key
// names one inner circuit, so the program binds a fold from its key alone.
type NullifierFoldProofSystem struct {
	TreeHeight       uint32
	BatchSize        uint32
	Run              uint32
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
	ConstraintSystem constraint.ConstraintSystem
}

func (ps *NullifierFoldProofSystem) WriteTo(w io.Writer) (int64, error) {
	var total int64
	var intBuf [4]byte
	for _, field := range []uint32{ps.TreeHeight, ps.BatchSize, ps.Run} {
		binary.BigEndian.PutUint32(intBuf[:], field)
		written, err := w.Write(intBuf[:])
		total += int64(written)
		if err != nil {
			return total, err
		}
	}

	for _, part := range []io.WriterTo{ps.ProvingKey, ps.VerifyingKey, ps.ConstraintSystem} {
		written, err := part.WriteTo(w)
		total += written
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (ps *NullifierFoldProofSystem) UnsafeReadFrom(r io.Reader) (int64, error) {
	var total int64
	var intBuf [4]byte
	for _, field := range []*uint32{&ps.TreeHeight, &ps.BatchSize, &ps.Run} {
		read, err := io.ReadFull(r, intBuf[:])
		total += int64(read)
		if err != nil {
			return total, err
		}
		*field = binary.BigEndian.Uint32(intBuf[:])
	}

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
