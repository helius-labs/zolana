package transaction

import (
	"math/big"
	"testing"

	"zolana/prover/prover-test/spp/protocol"
	transfereddsaonly "zolana/prover/prover/transfer_eddsa_only"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// The benchmark parameters must satisfy the production constraint system for
// every variant, otherwise a benchmark would measure proving a witness the
// server would never accept.
func TestBenchTransferParametersSolve(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	for _, variant := range benchEddsaVariants() {
		t.Run(variant.name, func(t *testing.T) {
			params, err := BuildTransferParameters(variant.variant, shape)
			if err != nil {
				t.Fatalf("build parameters: %v", err)
			}
			assignment, err := params.CreateWitness()
			if err != nil {
				t.Fatalf("create witness: %v", err)
			}
			witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatalf("new witness: %v", err)
			}
			ccs, err := transfereddsaonly.R1CSTransfer(
				uint32(shape.NInputs),
				uint32(shape.NOutputs),
				variant.variant,
			)
			if err != nil {
				t.Fatalf("compile circuit: %v", err)
			}
			if err := ccs.IsSolved(witness); err != nil {
				t.Fatalf("witness does not solve %s circuit: %v", variant.name, err)
			}

			// A tampered public input hash must break the same witness,
			// otherwise the check above would pass vacuously.
			params.PublicInputHash = new(big.Int).Add(params.PublicInputHash, big.NewInt(1))
			tampered, err := params.CreateWitness()
			if err != nil {
				t.Fatalf("create tampered witness: %v", err)
			}
			tamperedWitness, err := frontend.NewWitness(tampered, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatalf("new tampered witness: %v", err)
			}
			if err := ccs.IsSolved(tamperedWitness); err == nil {
				t.Fatalf("%s circuit accepted a tampered public input hash", variant.name)
			}
		})
	}
}

// The P256 rail has its own params type, witness builder, and public-input
// preimage, so it needs the same satisfiability guarantee as the eddsa rails.
func TestBenchP256TransferParametersSolve(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	params, err := BuildP256TransferParameters(shape)
	if err != nil {
		t.Fatalf("build parameters: %v", err)
	}
	assignment, err := params.CreateWitness()
	if err != nil {
		t.Fatalf("create witness: %v", err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	ccs, err := transfereddsaonly.R1CSP256Transfer(uint32(shape.NInputs), uint32(shape.NOutputs))
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}
	if err := ccs.IsSolved(witness); err != nil {
		t.Fatalf("witness does not solve p256 circuit: %v", err)
	}

	params.P256SigS = new(big.Int).Add(params.P256SigS, big.NewInt(1))
	tampered, err := params.CreateWitness()
	if err != nil {
		t.Fatalf("create tampered witness: %v", err)
	}
	tamperedWitness, err := frontend.NewWitness(tampered, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new tampered witness: %v", err)
	}
	if err := ccs.IsSolved(tamperedWitness); err == nil {
		t.Fatal("p256 circuit accepted a tampered signature")
	}
}

type benchVariant struct {
	name    string
	variant transfereddsaonly.Variant
}

func benchEddsaVariants() []benchVariant {
	return []benchVariant{
		{name: "confidential", variant: transfereddsaonly.ConfidentialVariant},
		{name: "zone", variant: transfereddsaonly.ZoneVariant},
		{name: "zone_authority", variant: transfereddsaonly.ZoneAuthorityVariant},
	}
}
