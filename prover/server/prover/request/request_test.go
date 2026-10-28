package request

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	txcircuit "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	merge "github.com/helius-labs/zolana/prover/server/prover/merge"
	transfer "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa"
)

func fixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/transfer-2x2.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

const fixtureDomain = `"domain":"0x0000000000000000000000000000000000000000000000000000000000000003"`

func TestParseNamesTheKey(t *testing.T) {
	for name, parse := range map[string]func([]byte) (*Request, error){"Parse": Parse, "ParseStrict": ParseStrict} {
		request, err := parse([]byte(fixture(t)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if request.Circuit != common.TransferConfidentialCircuitType || request.Inputs != 2 || request.Outputs != 2 ||
			request.KeyFile != "transfer_confidential_2_2.key" {
			t.Fatalf("%s: got %s %dx%d %q", name, request.Circuit, request.Inputs, request.Outputs, request.KeyFile)
		}
	}
}

func TestParseKeepsTheServerContract(t *testing.T) {
	body := fixture(t)
	for name, input := range map[string]string{
		"unknown field": strings.Replace(body, `"nInputs":2`, `"nInputs":2,"addedLater":1`, 1),
		"absent value":  strings.Replace(body, `"ringProgramId":`, `"ringProgramIdRenamed":`, 1),
	} {
		if _, err := Parse([]byte(input)); err != nil {
			t.Fatalf("Parse rejected %s: %v", name, err)
		}
		if _, err := ParseStrict([]byte(input)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("ParseStrict accepted %s: %v", name, err)
		}
	}
	unsupported := strings.Replace(strings.Replace(body, `"nInputs":2`, `"nInputs":7`, 1), `"nOutputs":2`, `"nOutputs":7`, 1)
	request, err := Parse([]byte(unsupported))
	if err != nil || request.KeyFile != "" {
		t.Fatalf("Parse of an unsupported shape: %v %q", err, request.KeyFile)
	}
	if _, err := ParseStrict([]byte(unsupported)); !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ParseStrict accepted an unsupported shape: %v", err)
	}
}

func TestParseRejectsNonCanonicalValues(t *testing.T) {
	modulus := "0x" + ecc.BN254.ScalarField().Text(16)
	input := strings.Replace(fixture(t), fixtureDomain, `"domain":"`+modulus+`"`, 1)
	for name, parse := range map[string]func([]byte) (*Request, error){"Parse": Parse, "ParseStrict": ParseStrict} {
		if _, err := parse([]byte(input)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%s accepted the field modulus: %v", name, err)
		}
	}
}

func TestParseStrictRejectsAdversarialInput(t *testing.T) {
	body := fixture(t)
	cases := []string{
		"{", "null", "[]", body + "{}",
		strings.Replace(body, `"nInputs":2`, `"nInputs":3.9`, 1),
		strings.Replace(body, `"nInputs":2`, `"nInputs":"2"`, 1),
		strings.Replace(body, `"nInputs":2`, `"nInputs":2,"nInputs":2`, 1),
		strings.Replace(body, `"nInputs":2`, `"NInputs":2`, 1),
		strings.Replace(body, fixtureDomain, `"domain":"not hex"`, 1),
		strings.Replace(body, fixtureDomain, `"domain":3`, 1),
		strings.Replace(body, fixtureDomain, `"domain":""`, 1),
		strings.Replace(body, fixtureDomain, `"domain":null`, 1),
		strings.Replace(body, fixtureDomain, `"domain":"-1"`, 1),
		strings.Replace(body, fixtureDomain, fixtureDomain+","+fixtureDomain, 1),
	}
	for index, input := range cases {
		if input == body {
			t.Fatalf("case %d did not change the fixture", index)
		}
		if _, err := ParseStrict([]byte(input)); !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrUnsupported) {
			t.Fatalf("case %d accepted: %v", index, err)
		}
	}
	for _, circuit := range []string{"transfer-eddsa-ring", "test-extension", "address-append", "unknown", ""} {
		input := strings.Replace(body, `"transfer-confidential"`, `"`+circuit+`"`, 1)
		if _, err := ParseStrict([]byte(input)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("circuit %q: %v", circuit, err)
		}
	}
}

func TestParseStrictRequiresEveryField(t *testing.T) {
	var object map[string]any
	if err := json.Unmarshal([]byte(fixture(t)), &object); err != nil {
		t.Fatal(err)
	}
	tested := 0
	var inspect func(map[string]any, reflect.Type)
	inspect = func(current map[string]any, schema reflect.Type) {
		fields := make(map[string]reflect.Type)
		optional := make(map[string]bool)
		jsonFields(schema, fields, optional)
		for name, field := range fields {
			if optional[name] {
				continue
			}
			value, present := current[name]
			if !present {
				t.Fatalf("fixture lacks %q", name)
			}
			delete(current, name)
			encoded, _ := json.Marshal(object)
			if _, err := ParseStrict(encoded); err == nil {
				t.Fatalf("missing %q was accepted", name)
			}
			current[name] = value
			tested++
			switch field.Kind() {
			case reflect.Struct:
				inspect(value.(map[string]any), field)
			case reflect.Slice:
				if field.Elem().Kind() == reflect.Struct {
					for _, item := range value.([]any) {
						inspect(item.(map[string]any), field.Elem())
					}
				}
			}
		}
	}
	inspect(object, reflect.TypeOf(transfer.TransferParametersJSON{}))
	if tested < 80 {
		t.Fatalf("only %d fields checked", tested)
	}
}

func TestParseNamesMergeKeysFromTheInputCount(t *testing.T) {
	zeros := func(n int) []*big.Int {
		values := make([]*big.Int, n)
		for i := range values {
			values[i] = big.NewInt(0)
		}
		return values
	}
	params := merge.MergeParameters{CircuitType: common.MergeCircuitType, OutputTreeID: big.NewInt(0), UserNullifierSecret: big.NewInt(1)}
	for i := 0; i < 8; i++ {
		params.Inputs = append(params.Inputs, merge.InputParams{
			StatePathElements:        zeros(txcircuit.StateTreeHeight),
			NullifierLowPathElements: zeros(txcircuit.NullifierTreeHeight),
			TreeSlot:                 big.NewInt(0),
		})
	}
	for i := 0; i < txcircuit.InputTrees; i++ {
		params.TreeSlots = append(params.TreeSlots, common.TreeSlotParams{ID: big.NewInt(0), UtxoRoot: big.NewInt(1), NullifierRoot: big.NewInt(1)})
	}
	body, err := json.Marshal(&params)
	if err != nil {
		t.Fatal(err)
	}
	request, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if request.KeyFile != "merge_8_1.key" || request.Inputs != 8 || request.Outputs != 1 {
		t.Fatalf("got %q %dx%d", request.KeyFile, request.Inputs, request.Outputs)
	}
	params.Inputs = params.Inputs[:7]
	body, _ = json.Marshal(&params)
	if _, err := Parse(body); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a 7-input merge was accepted: %v", err)
	}
}

func TestProveReportsTheKeyAndVerifies(t *testing.T) {
	if testing.Short() {
		t.Skip("groth16 setup of the 2x2 transfer circuit")
	}
	request, err := ParseStrict([]byte(fixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := request.assignment()
	if err != nil {
		t.Fatal(err)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, assignment, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	system := &common.TransferProofSystem{
		CircuitType: common.TransferConfidentialCircuitType, NInputs: 2, NOutputs: 2, Confidential: true,
		ProvingKey: pk, VerifyingKey: vk, ConstraintSystem: ccs, ProvingKeySha256: [32]byte{7},
	}
	proof, err := request.Prove(system, nil)
	if err != nil {
		t.Fatal(err)
	}
	if proof.ProvingKeySha256 != system.ProvingKeySha256 {
		t.Fatal("the proof does not report its key")
	}
	if err := request.Verify(system, proof); err != nil {
		t.Fatal(err)
	}
	other := *system
	other.NOutputs = 3
	if _, err := request.Prove(&other, nil); !errors.Is(err, ErrSystem) {
		t.Fatalf("a 2x3 system proved a 2x2 request: %v", err)
	}
	if err := request.Verify(&other, proof); !errors.Is(err, ErrSystem) {
		t.Fatalf("a 2x3 system verified a 2x2 request: %v", err)
	}
	ring, err := Parse([]byte(strings.Replace(fixture(t), `"transfer-confidential"`, `"transfer-ring"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Verify(system, proof); !errors.Is(err, ErrSystem) {
		t.Fatalf("a transfer-confidential proof verified a transfer-ring request: %v", err)
	}
}

// A signer width other than the protocol one names its own key, and a system
// for the protocol key refuses the request.
func TestParseNamesANonProtocolSignerWidthKey(t *testing.T) {
	body := strings.Replace(fixture(t), `"nInputs":2`, `"nInputs":2,"signerWidth":1`, 1)
	request, err := ParseStrict([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	want := common.ProofShape{Circuit: common.TransferConfidentialCircuitType, Inputs: 2, Outputs: 2, SignerWidth: 1}
	if request.Shape != want || request.KeyFile != "transfer_confidential_2_2_s1.key" {
		t.Fatalf("got %s %q", request.Shape, request.KeyFile)
	}
	protocol := &common.TransferProofSystem{CircuitType: common.TransferConfidentialCircuitType, NInputs: 2, NOutputs: 2}
	if err := request.check(protocol); !errors.Is(err, ErrSystem) {
		t.Fatalf("a protocol system accepted a width-1 request: %v", err)
	}
	protocol.SignerWidth = 1
	if err := request.check(protocol); err != nil {
		t.Fatal(err)
	}
}
