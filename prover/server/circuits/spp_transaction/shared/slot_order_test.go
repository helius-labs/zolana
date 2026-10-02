package shared_test

import (
	"fmt"
	"testing"
	. "zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type dummiesLastCircuit struct {
	Domains []frontend.Variable
}

func (c *dummiesLastCircuit) Define(api frontend.API) error {
	utxos := make([]UtxoCircuitFields, len(c.Domains))
	for i, domain := range c.Domains {
		utxos[i] = UtxoCircuitFields{Domain: domain}
	}
	AssertDummiesLast(api, utxos)
	return nil
}

func solveDummiesLast(domains []int) error {
	circuit := &dummiesLastCircuit{Domains: make([]frontend.Variable, len(domains))}
	assignment := &dummiesLastCircuit{Domains: make([]frontend.Variable, len(domains))}
	for i, domain := range domains {
		assignment.Domains[i] = domain
	}
	return test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
}

func TestDummiesLastAcceptsOnlyDummiesAfterADummy(t *testing.T) {
	domains := []int{UtxoDomain, AddressDomain, DummyDomain}
	for _, previous := range domains {
		for _, next := range domains {
			valid := previous != DummyDomain || next == DummyDomain
			t.Run(fmt.Sprintf("%d_then_%d", previous, next), func(t *testing.T) {
				err := solveDummiesLast([]int{previous, next})
				if (err == nil) != valid {
					t.Fatalf("solving error = %v, want valid %v", err, valid)
				}
			})
		}
	}
}

func TestDummiesLastHoldsAcrossTheWholeVector(t *testing.T) {
	cases := []struct {
		name    string
		domains []int
		valid   bool
	}{
		{"spends and addresses mixed, then dummies", []int{UtxoDomain, AddressDomain, UtxoDomain, AddressDomain, DummyDomain, DummyDomain}, true},
		{"address first", []int{AddressDomain, UtxoDomain, DummyDomain}, true},
		{"only real slots", []int{UtxoDomain, UtxoDomain, AddressDomain}, true},
		{"only dummies", []int{DummyDomain, DummyDomain, DummyDomain}, true},
		{"spend after a dummy further down", []int{UtxoDomain, DummyDomain, DummyDomain, UtxoDomain}, false},
		{"address after a dummy", []int{UtxoDomain, DummyDomain, AddressDomain}, false},
		{"dummy first", []int{DummyDomain, UtxoDomain}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := solveDummiesLast(tc.domains)
			if (err == nil) != tc.valid {
				t.Fatalf("solving error = %v, want valid %v", err, tc.valid)
			}
		})
	}
}
