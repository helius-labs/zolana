package shared_test

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type publicInputHashMutation struct {
	name string
	run  func()
}

type publicInputHashBindingOptions struct {
	includeRingProgramID       bool
	includeOutputOwnerPkHashes bool
	signerWidth                int
	extraMutations             []publicInputHashMutation
}

func assertPublicInputHashBindsEveryField(
	t *testing.T,
	circuit frontend.Circuit,
	assignment *testAssignment,
	materialize func() frontend.Circuit,
	refreshHash func(),
	options publicInputHashBindingOptions,
) {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}
	baselineHash := new(big.Int).Set(spptest.AsBigInt(assignment.PublicInputHash))
	baselineWitness, err := frontend.NewWitness(materialize(), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("create baseline witness: %v", err)
	}
	if err := ccs.IsSolved(baselineWitness); err != nil {
		t.Fatalf("baseline witness does not solve: %v", err)
	}

	var mutations []publicInputHashMutation
	// Change only the hash preimage, then restore the otherwise-valid witness so
	// each rejection is attributable to the aggregate public-input-hash check.
	refreshWithChangedField := func(target *frontend.Variable) {
		original := *target
		*target = nextPublicInputField(original)
		refreshHash()
		*target = original
	}
	for i := range assignment.Inputs {
		index := i
		mutations = append(mutations, publicInputHashMutation{
			name: fmt.Sprintf("nullifiers/%d", index),
			run:  func() { refreshWithChangedField(&assignment.Inputs[index].Nullifier) },
		})
	}
	for k := range assignment.TreeSlots {
		slot := k
		mutations = append(mutations,
			publicInputHashMutation{
				name: fmt.Sprintf("tree_slots/%d/id", slot),
				run:  func() { refreshWithChangedField(&assignment.TreeSlots[slot].ID) },
			},
			publicInputHashMutation{
				name: fmt.Sprintf("tree_slots/%d/utxo_root", slot),
				run:  func() { refreshWithChangedField(&assignment.TreeSlots[slot].UtxoRoot) },
			},
			publicInputHashMutation{
				name: fmt.Sprintf("tree_slots/%d/nullifier_root", slot),
				run:  func() { refreshWithChangedField(&assignment.TreeSlots[slot].NullifierRoot) },
			},
		)
	}
	mutations = append(mutations,
		publicInputHashMutation{name: "output_tree_id", run: func() {
			refreshWithChangedField(&assignment.OutputTreeID)
		}},
	)
	for i := range assignment.Outputs {
		index := i
		mutations = append(mutations, publicInputHashMutation{
			name: fmt.Sprintf("output_hashes/%d", index),
			run:  func() { refreshWithChangedField(&assignment.Outputs[index].Hash) },
		})
		if options.includeOutputOwnerPkHashes {
			mutations = append(mutations, publicInputHashMutation{
				name: fmt.Sprintf("output_owner_pk_hashes/%d", index),
				run:  func() { refreshWithChangedField(&assignment.Outputs[index].OwnerPkHash) },
			})
		}
	}
	mutations = append(mutations,
		publicInputHashMutation{name: "private_tx_hash", run: func() {
			refreshWithChangedField(&assignment.PrivateTxHash)
		}},
		publicInputHashMutation{name: "external_data_hash", run: func() {
			refreshWithChangedField(&assignment.ExternalDataHash)
		}},
	)
	for i := range assignment.PublicAssets {
		index := i
		mutations = append(mutations,
			publicInputHashMutation{
				name: fmt.Sprintf("public_assets/%d", index),
				run:  func() { refreshWithChangedField(&assignment.PublicAssets[index]) },
			},
			publicInputHashMutation{
				name: fmt.Sprintf("public_amounts/%d", index),
				run:  func() { refreshWithChangedField(&assignment.PublicAmounts[index]) },
			},
		)
	}
	if options.includeRingProgramID {
		mutations = append(mutations, publicInputHashMutation{name: "ring_program_id", run: func() {
			refreshWithChangedField(&assignment.RingProgramID)
		}})
	}
	if options.signerWidth < 1 || options.signerWidth > len(assignment.SignerPkHashes) {
		t.Fatalf(
			"invalid signer width: got %d for %d signer fields",
			options.signerWidth,
			len(assignment.SignerPkHashes),
		)
	}
	for i := range options.signerWidth {
		index := i
		mutations = append(mutations, publicInputHashMutation{
			name: fmt.Sprintf("signer_pk_hashes/%d", index),
			run:  func() { refreshWithChangedField(&assignment.SignerPkHashes[index]) },
		})
	}
	mutations = append(
		mutations,
		publicInputHashMutation{name: "allow_dummy_inputs", run: func() {
			refreshWithChangedField(&assignment.AllowDummyInputs)
		}},
	)
	mutations = append(mutations, options.extraMutations...)
	mutations = append(mutations, publicInputHashMutation{name: "public_input_hash", run: func() {
		assignment.PublicInputHash = nextPublicInputField(assignment.PublicInputHash)
	}})
	if got, want := len(mutations), publicFieldElementCount(t, materialize()); got != want {
		t.Fatalf("public input mutation count mismatch: got %d want %d", got, want)
	}

	for _, change := range mutations {
		t.Run(change.name, func(t *testing.T) {
			assignment.PublicInputHash = new(big.Int).Set(baselineHash)
			change.run()
			if baselineHash.Cmp(spptest.AsBigInt(assignment.PublicInputHash)) == 0 {
				t.Fatal("mutation did not change the public input hash")
			}
			witness, err := frontend.NewWitness(materialize(), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatalf("create witness: %v", err)
			}
			if err := ccs.IsSolved(witness); err == nil {
				t.Fatal("circuit accepted a public input hash computed from a changed field")
			}
		})
	}
}

func publicFieldElementCount(t testing.TB, circuit frontend.Circuit) int {
	t.Helper()
	value := reflect.Indirect(reflect.ValueOf(circuit))
	if !value.IsValid() || value.Kind() != reflect.Struct {
		t.Fatal("circuit is not a non-nil struct pointer")
	}
	public := value.FieldByName("Public")
	if !public.IsValid() || public.Kind() != reflect.Struct {
		t.Fatal("circuit does not have a Public struct")
	}
	count := 0
	for i := range public.NumField() {
		count += fieldElementCount(t, public.Type().Field(i).Name, public.Field(i))
	}
	return count
}

// fieldElementCount counts the frontend.Variable leaves of one public field: a
// variable, a slice or array of variables, or a slice of structs of variables
// such as []TreeSlot.
func fieldElementCount(t testing.TB, name string, field reflect.Value) int {
	t.Helper()
	switch field.Kind() {
	case reflect.Interface:
		return 1
	case reflect.Array, reflect.Slice:
		count := 0
		for i := range field.Len() {
			count += fieldElementCount(t, name, field.Index(i))
		}
		return count
	case reflect.Struct:
		count := 0
		for i := range field.NumField() {
			count += fieldElementCount(t, name, field.Field(i))
		}
		return count
	default:
		t.Fatalf("unsupported public field %q of kind %s", name, field.Kind())
		return 0
	}
}

func nextPublicInputField(value frontend.Variable) *big.Int {
	next := new(big.Int).Add(spptest.AsBigInt(value), big.NewInt(1))
	return next.Mod(next, ecc.BN254.ScalarField())
}
