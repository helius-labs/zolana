package policy

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// These are synthetic test keys and notes, never wallet material. The frozen
// fixtures exercise Go request assignment and Rust public-input verification.
func TestWriteTwoByThreeVectors(t *testing.T) {
	if os.Getenv("WRITE_TWO_BY_THREE_VECTORS") == "" {
		t.Skip("set WRITE_TWO_BY_THREE_VECTORS=1 to regenerate")
	}
	for _, mode := range []string{"ordinary", "anonymous", "delegate"} {
		kind := common.CustomRingPolicyTwoByThreeCircuitType
		if mode == "anonymous" {
			kind = common.CustomRingAnonymousPolicyTwoByThreeCircuitType
		}
		if mode == "delegate" {
			kind = common.CustomRingDelegatePolicyTwoByThreeCircuitType
		}
		w := publicTableAssignment(t, fullTwoByThreeStatement(t, mode == "anonymous"), mode == "delegate")
		loaded, err := common.ReadSystemFromFile(filepath.Join("../../../proving-keys", common.RingKeyFile(kind)))
		if err != nil {
			t.Fatal(err)
		}
		ps := loaded.(*common.RingProofSystem)
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		public, err := witness.Public()
		if err != nil {
			t.Fatal(err)
		}
		proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
		if err != nil {
			t.Fatal(err)
		}
		if err := groth16.Verify(proof, ps.VerifyingKey, public); err != nil {
			t.Fatal(err)
		}
		request := policyRequestJSON(reflect.ValueOf(w.Circuit.Policy))
		request["circuitType"] = string(kind)
		if mode == "delegate" {
			request = map[string]any{"circuitType": string(kind), "policy": request}
		}
		fields := []string{}
		for _, v := range public.Vector().(fr.Vector) {
			var n big.Int
			v.BigInt(&n)
			fields = append(fields, common.ToHex(&n))
		}
		write := func(path string, value any) {
			t.Helper()
			data, err := json.MarshalIndent(value, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		write(filepath.Join("../../../prover/custom_ring/testdata", string(kind)+".json"), request)
		write(filepath.Join("../../../../../custom-rings/sdk/tests/fixtures/prover-json", string(kind)+".json"), request)
		write(filepath.Join("../../../../../custom-rings/sdk/tests/fixtures", string(kind)+".json"), map[string]any{
			"request": request, "publicInputs": fields, "proof": &common.Proof{Proof: proof, ProvingKeySha256: ps.ProvingKeySha256},
		})
	}
}

func policyRequestJSON(v reflect.Value) map[string]any {
	out := map[string]any{}
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		if f.Tag.Get("gnark") == "-" {
			continue
		}
		if f.Anonymous {
			for k, v := range policyRequestJSON(v.Field(i)) {
				out[k] = v
			}
			continue
		}
		name := strings.ToLower(f.Name[:1]) + f.Name[1:]
		for _, suffix := range []string{"ID"} {
			if strings.HasSuffix(name, suffix) {
				name = strings.TrimSuffix(name, suffix) + "Id"
			}
		}
		if f.Name == "Rules" {
			name = "ruleEnc"
		}
		if f.Name == "NIn" {
			name = "nIn"
		}
		if f.Name == "NOut" {
			name = "nOut"
		}
		if f.Name == "ID" {
			name = "id"
		}
		out[name] = policyJSONValue(f.Name, v.Field(i))
	}
	return out
}

func policyJSONValue(name string, v reflect.Value) any {
	if v.Kind() == reflect.Struct {
		return policyRequestJSON(v)
	}
	if v.Kind() == reflect.Array || v.Kind() == reflect.Slice {
		if strings.Contains("|TxViewingSk|EphSk|AuditorPk|Salt|Sender|Recipient|RecipientViewingKey|", "|"+name+"|") {
			bytes := make([]byte, v.Len())
			for i := range bytes {
				bytes[i] = byte(wireInteger(v.Index(i).Interface()).Uint64())
			}
			return fmt.Sprintf("0x%x", bytes)
		}
		item := name
		if name == "Recipients" {
			item = "Recipient"
		}
		if name == "RecipientViewingKeys" {
			item = "RecipientViewingKey"
		}
		out := make([]any, v.Len())
		for i := range out {
			out[i] = policyJSONValue(item, v.Index(i))
		}
		return out
	}
	n := wireInteger(v.Interface())
	if strings.Contains("|Anonymous|ApprovalRequired|KeyEscrow|Present|", "|"+name+"|") {
		return n.Sign() != 0
	}
	if strings.Contains("|NIn|NOut|PolicyLen|InlineCount|LimitCount|ListId|Lists|Index|LowLists|", "|"+name+"|") {
		return n.Uint64()
	}
	return common.ToHex(n)
}

func wireInteger(v any) *big.Int {
	switch v := v.(type) {
	case *big.Int:
		return v
	case int:
		return big.NewInt(int64(v))
	case uint8:
		return new(big.Int).SetUint64(uint64(v))
	case uint64:
		return new(big.Int).SetUint64(v)
	default:
		panic(fmt.Sprintf("unexpected wire %T", v))
	}
}
