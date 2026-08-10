package common

import (
	"encoding/binary"
	"fmt"
	"io"
	"zolana/prover/prover/gpuprove"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

// MaxMergeChainLevels bounds the header a key file can carry. A deeper tree
// than this is unreachable long before the circuit stops compiling, because
// every level's tree-backed inputs go on the wire.
const MaxMergeChainLevels = 8

// MergeChainProofSystem holds the keys and constraints for one spp_merge_chain
// outer circuit.
//
// Keyed by the level shape, because both the inner verifying key and the tree
// are compile-time constants of the outer circuit. One outer key names one
// merge circuit and one tree, so the shielded pool binds a chain from its key
// alone.
type MergeChainProofSystem struct {
	Levels           []uint32
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
	ConstraintSystem constraint.ConstraintSystem
}

func (ps *MergeChainProofSystem) WriteTo(w io.Writer) (int64, error) {
	if len(ps.Levels) == 0 || len(ps.Levels) > MaxMergeChainLevels {
		return 0, fmt.Errorf("%d levels", len(ps.Levels))
	}

	var total int64
	var intBuf [4]byte
	for _, field := range append([]uint32{uint32(len(ps.Levels))}, ps.Levels...) {
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

func (ps *MergeChainProofSystem) UnsafeReadFrom(r io.Reader) (int64, error) {
	var total int64
	var intBuf [4]byte
	readUint32 := func() (uint32, error) {
		read, err := io.ReadFull(r, intBuf[:])
		total += int64(read)
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint32(intBuf[:]), nil
	}

	count, err := readUint32()
	if err != nil {
		return total, err
	}
	// The count drives an allocation, so it is bounded before the loop.
	if count == 0 || count > MaxMergeChainLevels {
		return total, fmt.Errorf("key header claims %d levels", count)
	}
	ps.Levels = make([]uint32, count)
	for i := range ps.Levels {
		if ps.Levels[i], err = readUint32(); err != nil {
			return total, err
		}
	}

	ps.ProvingKey = gpuprove.NewProvingKey()
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
