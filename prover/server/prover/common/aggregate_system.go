package common

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"zolana/prover/prover/gpuprove"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

// AggregateSlot names the inner circuit of one leg and, for a transfer rail,
// its shape. The swap take slot has no transfer shape, so its shape is zero.
type AggregateSlot struct {
	Inner    CircuitType
	NInputs  uint32
	NOutputs uint32
}

func (s AggregateSlot) Validate() error {
	if _, err := slotCode(s.Inner); err != nil {
		return err
	}
	if s.Inner == SwapTakeCircuitType {
		if s.NInputs != 0 || s.NOutputs != 0 {
			return fmt.Errorf("swap take slot carries shape %dx%d, want none", s.NInputs, s.NOutputs)
		}
		return nil
	}
	if s.NInputs == 0 || s.NOutputs == 0 {
		return fmt.Errorf("shape %dx%d has an empty side", s.NInputs, s.NOutputs)
	}
	return nil
}

// stem is the token a slot contributes to a key file name. Transfer rails
// reuse the stem of their inner key file.
func (s AggregateSlot) stem() string {
	switch s.Inner {
	case TransferConfidentialCircuitType:
		return "transfer_confidential"
	case TransferRingCircuitType:
		return "transfer_ring"
	case TransferP256RingCircuitType:
		return "transfer_p256_ring"
	case TransferRingAuthorityCircuitType:
		return "transfer_ring_authority"
	case SwapTakeCircuitType:
		return "swap_take"
	default:
		return string(s.Inner)
	}
}

func (s AggregateSlot) token() string {
	if s.Inner == SwapTakeCircuitType {
		return s.stem()
	}
	return fmt.Sprintf("%s_%d_%d", s.stem(), s.NInputs, s.NOutputs)
}

// UniformSlots reports the single slot a batch repeats, if it repeats one.
func UniformSlots(slots []AggregateSlot) (AggregateSlot, bool) {
	if len(slots) == 0 {
		return AggregateSlot{}, false
	}
	for _, slot := range slots[1:] {
		if slot != slots[0] {
			return AggregateSlot{}, false
		}
	}
	return slots[0], true
}

// AggregateKeyName leads with "aggregate" so ReadSystemFromFile picks the
// aggregate header before the transfer one. A uniform batch keeps the name its
// key file already has. A mixed batch lists its slots in order, "-" separated,
// because the hash-chain statement binds slot order.
func AggregateKeyName(slots []AggregateSlot) string {
	if s, ok := UniformSlots(slots); ok && s.Inner != SwapTakeCircuitType {
		return fmt.Sprintf("aggregate_%s_b%d.key", s.token(), len(slots))
	}
	tokens := make([]string, len(slots))
	for i, slot := range slots {
		tokens[i] = slot.token()
	}
	return fmt.Sprintf("aggregate_mix_%s_b%d.key", strings.Join(tokens, "-"), len(slots))
}

// AggregateProofSystem holds the keys and constraints for one spp_aggregate
// outer circuit.
//
// Keyed by the ordered slot list, because every slot's inner verifying key is
// a compile-time constant of the outer circuit. One outer key names one slot
// list, so the shielded pool binds a batch from the selector alone.
type AggregateProofSystem struct {
	Slots            []AggregateSlot
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
	ConstraintSystem constraint.ConstraintSystem
}

func (ps *AggregateProofSystem) Batch() uint32 {
	return uint32(len(ps.Slots))
}

func (ps *AggregateProofSystem) KeyName() string {
	return AggregateKeyName(ps.Slots)
}

// Slot codes are part of the key file format. Append only, never renumber. A
// changed code silently reinterprets an existing key file.
const (
	railTransferConfidential  uint32 = 1
	railTransferRing          uint32 = 2
	railTransferP256Ring      uint32 = 3
	railTransferRingAuthority uint32 = 4
	slotSwapTake              uint32 = 5

	// headerMixed marks the mixed-batch header. A uniform header leads with a
	// rail code, so the sentinel must stay outside the code space.
	headerMixed uint32 = 0xffffffff
)

var railCodes = map[CircuitType]uint32{
	TransferConfidentialCircuitType:  railTransferConfidential,
	TransferRingCircuitType:          railTransferRing,
	TransferP256RingCircuitType:      railTransferP256Ring,
	TransferRingAuthorityCircuitType: railTransferRingAuthority,
}

// AggregatableRail reports whether a rail can fill a whole batch on its own,
// and its key-file code. Merge and address-append have no aggregate
// instruction, and a batch of take proofs alone has nothing to settle.
func AggregatableRail(inner CircuitType) (uint32, error) {
	code, ok := railCodes[inner]
	if !ok {
		return 0, fmt.Errorf("rail %q cannot be batched", inner)
	}
	return code, nil
}

func slotCode(inner CircuitType) (uint32, error) {
	if inner == SwapTakeCircuitType {
		return slotSwapTake, nil
	}
	return AggregatableRail(inner)
}

func slotFromCode(code uint32) (CircuitType, error) {
	if code == slotSwapTake {
		return SwapTakeCircuitType, nil
	}
	for rail, candidate := range railCodes {
		if candidate == code {
			return rail, nil
		}
	}
	return "", fmt.Errorf("unknown slot code %d", code)
}

func writeUint32s(w io.Writer, fields ...uint32) (int64, error) {
	var total int64
	var intBuf [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(intBuf[:], field)
		written, err := w.Write(intBuf[:])
		total += int64(written)
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func readUint32s(r io.Reader, fields ...*uint32) (int64, error) {
	var total int64
	var intBuf [4]byte
	for _, field := range fields {
		read, err := io.ReadFull(r, intBuf[:])
		total += int64(read)
		if err != nil {
			return total, err
		}
		*field = binary.BigEndian.Uint32(intBuf[:])
	}
	return total, nil
}

// WriteTo writes the rail-code header for a uniform batch of one rail, so
// existing uniform key files stay byte-identical. A mixed batch writes the
// sentinel, the slot count, and the slot list in order.
func (ps *AggregateProofSystem) WriteTo(w io.Writer) (int64, error) {
	var total int64
	if s, ok := UniformSlots(ps.Slots); ok && s.Inner != SwapTakeCircuitType {
		code, err := AggregatableRail(s.Inner)
		if err != nil {
			return 0, err
		}
		total, err = writeUint32s(w, code, s.NInputs, s.NOutputs, ps.Batch())
		if err != nil {
			return total, err
		}
	} else {
		written, err := writeUint32s(w, headerMixed, uint32(len(ps.Slots)))
		total += written
		if err != nil {
			return total, err
		}
		for _, slot := range ps.Slots {
			code, err := slotCode(slot.Inner)
			if err != nil {
				return total, err
			}
			written, err = writeUint32s(w, code, slot.NInputs, slot.NOutputs)
			total += written
			if err != nil {
				return total, err
			}
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

func (ps *AggregateProofSystem) UnsafeReadFrom(r io.Reader) (int64, error) {
	var total int64
	var lead uint32
	read, err := readUint32s(r, &lead)
	total += read
	if err != nil {
		return total, err
	}

	if lead == headerMixed {
		var count uint32
		read, err = readUint32s(r, &count)
		total += read
		if err != nil {
			return total, err
		}
		ps.Slots = make([]AggregateSlot, count)
		for i := range ps.Slots {
			var code uint32
			read, err = readUint32s(r, &code, &ps.Slots[i].NInputs, &ps.Slots[i].NOutputs)
			total += read
			if err != nil {
				return total, err
			}
			if ps.Slots[i].Inner, err = slotFromCode(code); err != nil {
				return total, err
			}
		}
	} else {
		var nInputs, nOutputs, batch uint32
		read, err = readUint32s(r, &nInputs, &nOutputs, &batch)
		total += read
		if err != nil {
			return total, err
		}
		inner, err := slotFromCode(lead)
		if err != nil {
			return total, err
		}
		slot := AggregateSlot{Inner: inner, NInputs: nInputs, NOutputs: nOutputs}
		ps.Slots = make([]AggregateSlot, batch)
		for i := range ps.Slots {
			ps.Slots[i] = slot
		}
	}

	ps.ProvingKey = gpuprove.NewProvingKey()
	read, err = ps.ProvingKey.UnsafeReadFrom(r)
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
