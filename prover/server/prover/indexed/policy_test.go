package indexed

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"testing"

	"zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"
	ring "zolana/prover/prover/custom_ring"
	"zolana/prover/prover/transcript"
)

func policyFixture(t *testing.T, enabled bool) (Request, response[stateProof], response[nullifierProof]) {
	t.Helper()
	transaction, state, exclusion := fixture(t)
	zeroFields := func(count int) []string {
		result := make([]string, count)
		for i := range result {
			result[i] = "0x" + strings.Repeat("00", 32)
		}
		return result
	}
	openings := func(count int) []map[string]any {
		result := make([]map[string]any, count)
		for i := range result {
			result[i] = map[string]any{"domain": "0x" + strings.Repeat("00", 31) + "01", "treeId": "0x" + strings.Repeat("00", 32), "ownerPkHash": "0x" + strings.Repeat("00", 32), "nullifierPk": "0x" + strings.Repeat("00", 32), "asset": "0x" + strings.Repeat("00", 32), "amount": "0x" + strings.Repeat("00", 32), "blinding": "0x" + strings.Repeat("00", 32), "dataHash": "0x" + strings.Repeat("00", 32), "ringDataHash": "0x" + strings.Repeat("00", 32), "ringProgramId": "0x" + strings.Repeat("00", 32)}
		}
		return result
	}
	answers := make([]map[string]any, 10)
	lookups := make([]Lookup, 10)
	for i := range answers {
		answers[i] = map[string]any{"enabled": false, "treeSlot": 0, "mode": 1, "listId": 1, "state": 1, "absentBranch": 1, "member": "0x" + strings.Repeat("00", 31) + "01", "contentHash": "0x" + strings.Repeat("00", 32), "version": 0, "blinding": "0x" + strings.Repeat("00", 32)}
	}
	if enabled {
		answers[0]["enabled"], answers[0]["absentBranch"] = true, 2
		lookups[0] = Lookup{TreeSlot: 0, Commitment: &state.Proofs[0].Leaf, Nullifier: &exclusion.Proofs[0].Leaf}
	}
	sources, velocity := make([]map[string]any, 8), make([]map[string]any, 8)
	for i := range sources {
		sources[i] = map[string]any{"listId": 0, "ownerHash": "0x" + strings.Repeat("00", 32)}
	}
	for i := range velocity {
		velocity[i] = map[string]any{"asset": "0x" + strings.Repeat("00", 32), "cap": "0x" + strings.Repeat("00", 32), "cosignAbove": "0x" + strings.Repeat("00", 32)}
	}
	rules := make([]string, 16)
	for i := range rules {
		rules[i] = "0x" + strings.Repeat("00", 32)
	}
	prepared := map[string]any{
		"circuitType":   common.CustomRingPolicyCircuitType,
		"privateTxHash": "0x" + strings.Repeat("00", 31) + "01", "txViewingSk": "0x" + strings.Repeat("00", 31) + "01", "ephSk": "0x" + strings.Repeat("00", 31) + "02",
		"auditorPk": "0x" + hex.EncodeToString(elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)),
		"salt":      "0x" + strings.Repeat("00", 16), "nIn": 1, "nOut": 1, "inputs": openings(5), "outputs": openings(4),
		"addressChain": "0x" + strings.Repeat("00", 32), "externalDataHash": "0x" + strings.Repeat("00", 32), "privateTxBlinding": "0x" + strings.Repeat("00", 32), "sources": sources, "policyLen": 0, "ruleEnc": rules,
		"inlineAssets": zeroFields(8), "inlineLimits": zeroFields(8), "inlineCount": 0, "windowSlots": 0, "velocity": velocity, "velocityCount": 0,
		"addressTreeId": "0x" + strings.Repeat("00", 32), "ringId": "0x" + strings.Repeat("00", 31) + "01", "namespaceOwnerHash": "0x" + strings.Repeat("00", 31) + "01", "windowIndex": 0, "approvalRequired": false, "keyEscrow": false, "keyRegistryRoot": "0x" + strings.Repeat("00", 32),
		"record": map[string]any{"version": 0, "window": 0, "commitment": "0x" + strings.Repeat("00", 32), "salt": "0x" + strings.Repeat("00", 32), "assets": zeroFields(8), "spent": zeroFields(8), "nextSalt": "0x" + strings.Repeat("00", 32)}, "answers": answers,
	}
	tree := transaction.Trees[0]
	tree.Fallback = &common.ResolvedTree{Tree: tree.Address, ID: tree.ID, UtxoRoot: state.Proofs[0].Root.hex(), NullifierRoot: exclusion.Proofs[0].Root.hex(), UtxoRootIndex: state.Proofs[0].RootIndex, NullifierRootIndex: exclusion.Proofs[0].RootIndex}
	return Request{CircuitType: common.CustomRingPolicyCircuitType, Prepared: encoded(t, prepared), Trees: []Tree{tree}, Inputs: lookups, PublicInputs: zeroFields(19)}, state, exclusion
}

func TestPolicyResolvesOnlyEnabledFacts(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		request, state, exclusion := policyFixture(t, enabled)
		resolver, err := NewResolver(Config{URL: "http://indexer.test", Concurrency: 1})
		if err != nil {
			t.Fatal(err)
		}
		resolver.client.Transport = roundTripFunc(func(httpRequest *http.Request) (*http.Response, error) {
			if !enabled {
				t.Error("disabled facts queried indexer")
			}
			var body struct {
				Method string      `json:"method"`
				Params proofParams `json:"params"`
			}
			if err := json.NewDecoder(httpRequest.Body).Decode(&body); err != nil {
				return nil, err
			}
			if len(body.Params.Leaves) != 1 {
				t.Error("unexpected enabled fact count")
			}
			var result any
			switch body.Method {
			case "getMerkleProofs":
				result = state
			case "getNonInclusionProofs":
				exclusion.Proofs = exclusion.Proofs[:1]
				result = exclusion
			default:
				t.Fatal("unexpected indexer method")
			}
			data := encoded(t, map[string]any{"jsonrpc": "2.0", "id": body.Method, "result": result})
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(data))}, nil
		})
		resolved, err := resolver.Resolve(context.Background(), encoded(t, request))
		if err != nil {
			t.Fatal(err)
		}
		var params ring.PolicyParameters
		if err := json.Unmarshal(resolved.Payload, &params); err != nil {
			t.Fatal(err)
		}
		if common.FeHex(params.PublicInputHash) != resolved.Resolution.PublicInputHash {
			t.Fatal("policy statement mismatch")
		}
		if enabled && params.ListFacts[0].Low.Cmp(new(big.Int).SetBytes(exclusion.Proofs[0].LowElement[:])) != 0 {
			t.Fatal("unresolved exclusion")
		}
	}
}

func TestPolicyRejectsNullFactsInEveryWrapper(t *testing.T) {
	for _, circuit := range []common.CircuitType{common.CustomRingPolicyCircuitType, common.CustomRingDelegatePolicyCircuitType, common.CustomRingCompressedPolicyCircuitType} {
		t.Run(string(circuit), func(t *testing.T) {
			request, _, _ := policyFixture(t, false)
			var base map[string]any
			if err := json.Unmarshal(request.Prepared, &base); err != nil {
				t.Fatal(err)
			}
			base["answers"].([]any)[0] = nil
			request.CircuitType = circuit
			if circuit == common.CustomRingPolicyCircuitType {
				request.Prepared = encoded(t, base)
			} else {
				request.Prepared = encoded(t, map[string]any{"circuitType": circuit, "policy": base, "transactionSalt": "0x" + strings.Repeat("00", 16)})
			}
			if circuit == common.CustomRingCompressedPolicyCircuitType {
				request.PublicInputs = append(request.PublicInputs, "0x0")
			}
			if Validate(encoded(t, request)) == nil {
				t.Fatal("null fact accepted")
			}
		})
	}
}

func TestPolicyRegistryBindsOwnerKeyAndAnchor(t *testing.T) {
	request, _, _ := policyFixture(t, false)
	var base map[string]any
	if err := json.Unmarshal(request.Prepared, &base); err != nil {
		t.Fatal(err)
	}
	output := base["outputs"].([]any)[0].(map[string]any)
	output["domain"] = common.ToHex(big.NewInt(shared.UtxoDomain))
	output["ownerPkHash"], output["nullifierPk"] = common.ToHex(big.NewInt(5)), common.ToHex(big.NewInt(6))
	ciphertext := bytes.Repeat([]byte{7}, 32)
	ctHash, _ := transcript.HashFields([]*big.Int{new(big.Int).SetBytes(ciphertext[:31]), new(big.Int).SetBytes(ciphertext[31:])})
	keyHash, _ := transcript.HashFields([]*big.Int{big.NewInt(6), ctHash})
	leaf, _ := transcript.HashFields([]*big.Int{big.NewInt(5), big.NewInt(8), keyHash})
	root := leaf
	path := make([]Hash, 40)
	for i := range path {
		pair := []*big.Int{root, new(big.Int)}
		if i == 0 {
			pair[0], pair[1] = pair[1], pair[0]
		}
		root, _ = transcript.HashFields(pair)
	}
	rootHash, _ := hashField(root)
	member, _ := hashField(big.NewInt(5))
	next, _ := hashField(big.NewInt(8))
	request.Registry = &RegistryRequest{Ring: request.Trees[0].Address, Root: rootHash, NextIndex: 2}
	base["keyEscrow"], base["keyRegistryRoot"] = true, common.ToHex(root)
	request.Prepared = encoded(t, base)
	for _, circuit := range []common.CircuitType{common.CustomRingPolicyCircuitType, common.CustomRingDepositCircuitType} {
		for _, mutation := range []string{"", "owner", "root", "count", "index", "path", "ciphertext", "nullifier", "stale", "unregistered"} {
			t.Run(string(circuit)+"/"+mutation, func(t *testing.T) {
				resolver, err := NewResolver(Config{URL: "http://indexer.test", Concurrency: 1})
				if err != nil {
					t.Fatal(err)
				}
				entry := registryEntry{Root: rootHash, Member: member, Next: next, NextIndex: 2, Index: 1, Ciphertext: append([]byte{}, ciphertext...), Proof: append([]Hash{}, path...)}
				switch mutation {
				case "owner":
					entry.Member[31]++
				case "root":
					entry.Root[31]++
				case "count":
					entry.NextIndex++
				case "index":
					entry.Index = 0
				case "path":
					entry.Proof[1][31]++
				case "ciphertext":
					entry.Ciphertext[0]++
				}
				current := request
				if mutation == "nullifier" {
					output["nullifierPk"] = common.ToHex(big.NewInt(7))
					current.Prepared = encoded(t, base)
					output["nullifierPk"] = common.ToHex(big.NewInt(6))
				}
				if circuit == common.CustomRingDepositCircuitType {
					var policy map[string]any
					if err := json.Unmarshal(current.Prepared, &policy); err != nil {
						t.Fatal(err)
					}
					output := policy["outputs"].([]any)[0].(map[string]any)
					column := func(first any) []any {
						values := make([]any, 8)
						for i := range values {
							values[i] = common.ToHex(new(big.Int))
						}
						values[0] = first
						return values
					}
					current.CircuitType = circuit
					current.Trees = nil
					current.Inputs = nil
					current.PublicInputs = []string{"0x0"}
					current.Prepared = encoded(t, map[string]any{"circuitType": circuit, "publicInputHash": common.ToHex(new(big.Int)), "contextHash": common.ToHex(new(big.Int)), "count": 1, "ownerPkHashes": column(output["ownerPkHash"]), "nullifierPks": column(output["nullifierPk"]), "blindings": column(common.ToHex(big.NewInt(1))), "keyEscrow": true, "keyRegistryRoot": base["keyRegistryRoot"], "ephSk": base["ephSk"], "auditorPk": base["auditorPk"]})
				}
				if mutation == "stale" {
					current.MinContextSlot = 1
				}
				calls := 0
				resolver.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					var query struct {
						Method string
						Params struct {
							Member            Hash
							ExpectedRoot      Hash
							ExpectedNextIndex uint64
						}
					}
					if err := json.NewDecoder(req.Body).Decode(&query); err != nil {
						t.Fatal(err)
					}
					if query.Method != "getRingKeyRegistryEntry" || query.Params.Member != member || query.Params.ExpectedRoot != rootHash || query.Params.ExpectedNextIndex != 2 {
						t.Fatal("registry query mismatch")
					}
					reply := map[string]any{"jsonrpc": "2.0", "id": query.Method, "result": entry}
					if mutation == "unregistered" {
						reply = map[string]any{"jsonrpc": "2.0", "id": query.Method, "error": map[string]any{"code": -32072}}
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(encoded(t, reply)))}, nil
				})
				resolved, err := resolver.Resolve(context.Background(), encoded(t, current))
				if (err == nil) != (mutation == "") {
					t.Fatalf("unexpected registry validation result %v", err)
				}
				var unregistered *UnregisteredMemberError
				if slices.Contains([]string{"path", "ciphertext", "nullifier", "unregistered"}, mutation) != errors.As(err, &unregistered) || (unregistered != nil && unregistered.Member != member) {
					t.Fatalf("unexpected unregistered member classification %v", err)
				}
				if mutation == "stale" {
					if !errors.Is(err, ErrIndexerNotReady) {
						t.Fatalf("slot lag is not retryable %v", err)
					}
					entry.Context.Slot = current.MinContextSlot
					if _, err := resolver.Resolve(context.Background(), encoded(t, current)); err != nil || calls != 2 {
						t.Fatalf("fresh membership rejected %v", err)
					}
				}
				if mutation == "" && circuit == common.CustomRingDepositCircuitType {
					var params ring.DepositParameters
					if err := json.Unmarshal(resolved.Payload, &params); err != nil {
						t.Fatal(err)
					}
					if params.Keys[0] == nil || params.Keys[0].Index != 1 || params.Keys[0].CtHash.Cmp(ctHash) != 0 || calls != 1 || resolved.Resolution.PublicInputHash != common.FeHex(params.PublicInputHash) {
						t.Fatal("unresolved deposit membership")
					}
					for _, key := range params.Keys[1:] {
						if key != nil {
							t.Fatal("nonzero deposit padding")
						}
					}
				}
				if mutation == "" && circuit == common.CustomRingPolicyCircuitType {
					var params ring.PolicyParameters
					if err := json.Unmarshal(resolved.Payload, &params); err != nil {
						t.Fatal(err)
					}
					if params.Outputs[0].Key == nil || params.Outputs[0].Key.Index != 1 || params.Outputs[0].Key.CtHash.Cmp(ctHash) != 0 || calls != 1 {
						t.Fatal("unresolved registry key")
					}
				}
			})
		}
	}
}

func TestRegistryProjectionLagRemainsRetryable(t *testing.T) {
	for _, code := range []int{-32070, -32071, -32603} {
		resolver, err := NewResolver(Config{URL: "http://indexer.test", Concurrency: 1})
		if err != nil {
			t.Fatal(err)
		}
		resolver.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(encoded(t, map[string]any{"jsonrpc": "2.0", "id": "getRingKeyRegistryEntry", "error": map[string]any{"code": code, "message": "private upstream details"}})))}, nil
		})
		_, err = resolver.rpc(context.Background(), "getRingKeyRegistryEntry", nil)
		if errors.Is(err, ErrIndexerNotReady) != (code != -32603) {
			t.Fatalf("unexpected retry classification for %d", code)
		}
		if strings.Contains(err.Error(), "private") {
			t.Fatal("upstream details leaked")
		}
	}
}
