package transaction

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	txcircuit "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnarkio "github.com/consensys/gnark/io"
)

// ProofSystem holds keys and constraints for one transaction circuit shape and
// ownership rail. RequiresP256 selects the P256-capable circuit (true) or the
// Solana-only variant (false, ~7x fewer constraints). It is serialized in the
// key-file header so a loaded system self-describes its rail.
type ProofSystem struct {
	Shape            protocol.Shape
	RequiresP256     bool
	ConstraintSystem constraint.ConstraintSystem
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
}

func Compile(shape protocol.Shape, requiresP256 bool) (constraint.ConstraintSystem, error) {
	var (
		circuit *txcircuit.Circuit
		err     error
	)
	txShape := txcircuit.Shape{NInputs: shape.NInputs, NOutputs: shape.NOutputs}
	if requiresP256 {
		circuit, err = txcircuit.NewTransferP256ZoneCircuit(txShape)
	} else {
		circuit, err = txcircuit.NewTransferZoneCircuit(txShape)
	}
	if err != nil {
		return nil, err
	}
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		circuit,
		frontend.WithCompressThreshold(300),
	)
}

func Setup(shape protocol.Shape, requiresP256 bool) (*ProofSystem, error) {
	ccs, err := Compile(shape, requiresP256)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &ProofSystem{
		Shape:            shape,
		RequiresP256:     requiresP256,
		ConstraintSystem: ccs,
		ProvingKey:       pk,
		VerifyingKey:     vk,
	}, nil
}

func Prove(ps *ProofSystem, assignment *txcircuit.Circuit) (groth16.Proof, error) {
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	return groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
}

func Verify(ps *ProofSystem, assignment *txcircuit.Circuit, proof groth16.Proof) error {
	witness, err := frontend.NewWitness(
		assignment,
		ecc.BN254.ScalarField(),
		frontend.PublicOnly(),
	)
	if err != nil {
		return err
	}
	return groth16.Verify(proof, ps.VerifyingKey, witness)
}

func WriteProofSystem(ps *ProofSystem, path string, vkeyPath string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := ps.WriteTo(file); err != nil {
		return err
	}
	if vkeyPath != "" {
		return WriteVerifyingKeyText(ps.VerifyingKey, vkeyPath)
	}
	return nil
}

func ReadProofSystem(path string) (*ProofSystem, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	ps := new(ProofSystem)
	if _, err := ps.UnsafeReadFrom(file); err != nil {
		return nil, err
	}
	return ps, nil
}

func WriteVerifyingKeyText(vk groth16.VerifyingKey, path string) error {
	var buf bytes.Buffer
	if _, err := vk.(gnarkio.WriterRawTo).WriteRawTo(&buf); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString("["); err != nil {
		return err
	}
	for i, b := range buf.Bytes() {
		if i > 0 {
			if _, err := file.WriteString(" "); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(file, "%d", b); err != nil {
			return err
		}
	}
	_, err = file.WriteString("]")
	return err
}

func boolToU32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

func (ps *ProofSystem) WriteTo(w io.Writer) (int64, error) {
	var total int64
	var buf [4]byte
	// Header: NInputs, NOutputs, RequiresP256. Serializing the ownership rail
	// makes the key self-describing — the prover binds the matching circuit
	// without inferring the rail from the filename.
	fields := []uint32{uint32(ps.Shape.NInputs), uint32(ps.Shape.NOutputs), boolToU32(ps.RequiresP256)}
	for _, field := range fields {
		binary.BigEndian.PutUint32(buf[:], field)
		n, err := w.Write(buf[:])
		total += int64(n)
		if err != nil {
			return total, err
		}
	}

	n, err := ps.ProvingKey.WriteTo(w)
	total += n
	if err != nil {
		return total, err
	}
	n, err = ps.VerifyingKey.WriteTo(w)
	total += n
	if err != nil {
		return total, err
	}
	n, err = ps.ConstraintSystem.WriteTo(w)
	total += n
	if err != nil {
		return total, err
	}
	return total, nil
}

func (ps *ProofSystem) UnsafeReadFrom(r io.Reader) (int64, error) {
	var total int64
	var buf [4]byte
	var nInputs, nOutputs, requiresP256 uint32
	fields := []*uint32{&nInputs, &nOutputs, &requiresP256}
	for _, field := range fields {
		n, err := io.ReadFull(r, buf[:])
		total += int64(n)
		if err != nil {
			return total, err
		}
		*field = binary.BigEndian.Uint32(buf[:])
	}
	shape, err := protocol.NewShape(int(nInputs), int(nOutputs))
	if err != nil {
		return total, err
	}
	ps.Shape = shape
	ps.RequiresP256 = requiresP256 != 0

	ps.ProvingKey = groth16.NewProvingKey(ecc.BN254)
	n, err := ps.ProvingKey.UnsafeReadFrom(r)
	total += n
	if err != nil {
		return total, err
	}
	ps.VerifyingKey = groth16.NewVerifyingKey(ecc.BN254)
	n, err = ps.VerifyingKey.UnsafeReadFrom(r)
	total += n
	if err != nil {
		return total, err
	}
	ps.ConstraintSystem = groth16.NewCS(ecc.BN254)
	n, err = ps.ConstraintSystem.ReadFrom(r)
	total += n
	if err != nil {
		return total, err
	}
	return total, nil
}
