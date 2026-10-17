package indexed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	ring "github.com/helius-labs/zolana/prover/server/prover/custom_ring"
	"github.com/helius-labs/zolana/prover/server/prover/transcript"
)

// hostRegistry holds the sentinel and one record for member 5 whose key escrows nullifier 6.
type hostRegistry struct {
	root       Hash
	member     Hash
	ciphertext []byte
	ctHash     *big.Int
	record     recordJSON
	sentinel   recordJSON
	path       []Hash
}

func newHostRegistry(t *testing.T) hostRegistry {
	t.Helper()
	ciphertext := bytes.Repeat([]byte{7}, 32)
	ctHash, _ := transcript.HashFields([]*big.Int{new(big.Int).SetBytes(ciphertext[:31]), new(big.Int).SetBytes(ciphertext[31:])})
	escrowKey, _ := transcript.HashFields([]*big.Int{big.NewInt(6), ctHash})
	fieldMax := new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
	toHash := func(value *big.Int) Hash {
		hash, err := hashField(value)
		if err != nil {
			t.Fatal(err)
		}
		return hash
	}
	sentinelLeaf, _ := transcript.HashFields([]*big.Int{big.NewInt(0), fieldMax, big.NewInt(0), big.NewInt(0)})
	recordLeaf, _ := transcript.HashFields([]*big.Int{big.NewInt(5), fieldMax, big.NewInt(0b101), escrowKey})
	root, _ := transcript.HashFields([]*big.Int{sentinelLeaf, recordLeaf})
	for range 19 {
		root, _ = transcript.HashFields([]*big.Int{root, new(big.Int)})
	}
	path := make([]Hash, 20)
	path[0] = toHash(sentinelLeaf)
	return hostRegistry{
		root: toHash(root), member: toHash(big.NewInt(5)), ciphertext: ciphertext, ctHash: ctHash,
		record:   recordJSON{Member: toHash(big.NewInt(5)), Next: toHash(fieldMax), Lists: 0b101, EscrowKey: toHash(escrowKey), Ciphertext: ciphertext},
		sentinel: recordJSON{Member: Hash{}, Next: toHash(fieldMax), Lists: 0, EscrowKey: Hash{}},
		path:     path,
	}
}

func (h hostRegistry) anchor(ringAddress string) *RegistryRequest {
	return &RegistryRequest{Ring: ringAddress, Root: h.root, NextIndex: 2}
}

// present answers for member 5, absent for any member the sentinel brackets below 5.
func (h hostRegistry) present() memberRecordResponse {
	record := h.record
	record.Ciphertext = append([]byte{}, h.ciphertext...)
	return memberRecordResponse{Root: h.root, NextIndex: 2, Present: true, Record: &record, Index: 1, Path: append([]Hash{}, h.path...)}
}

func (h hostRegistry) absent() memberRecordResponse {
	lowPath := make([]Hash, 20)
	leaf, _ := transcript.HashFields([]*big.Int{big.NewInt(5), new(big.Int).SetBytes(h.record.Next[:]), big.NewInt(0b101), new(big.Int).SetBytes(h.record.EscrowKey[:])})
	lowPath[0], _ = hashField(leaf)
	return memberRecordResponse{Root: h.root, NextIndex: 2, Low: &lowRecordJSON{recordJSON: h.sentinel, Index: 0, Path: lowPath}}
}

func zeroHex() string { return "0x" + strings.Repeat("00", 32) }

func policyFixture(t *testing.T, registry hostRegistry) Request {
	t.Helper()
	transaction, state, exclusion := fixture(t)
	zeroFields := func(count int) []string {
		result := make([]string, count)
		for i := range result {
			result[i] = zeroHex()
		}
		return result
	}
	openings := func(count int) []map[string]any {
		result := make([]map[string]any, count)
		for i := range result {
			result[i] = map[string]any{"domain": "0x" + strings.Repeat("00", 31) + "01", "treeId": zeroHex(), "ownerPkHash": zeroHex(), "nullifierPk": zeroHex(), "asset": zeroHex(), "amount": zeroHex(), "blinding": zeroHex(), "dataHash": zeroHex(), "ringDataHash": zeroHex(), "ringProgramId": zeroHex()}
		}
		return result
	}
	sources, limits := make([]map[string]any, 8), make([]map[string]any, 8)
	for i := range sources {
		sources[i] = map[string]any{"listId": 0, "registry": zeroHex()}
	}
	for i := range limits {
		limits[i] = map[string]any{"asset": zeroHex(), "cap": zeroHex(), "cosignAbove": zeroHex()}
	}
	prepared := map[string]any{
		"circuitType":   common.CustomRingPolicyCircuitType,
		"privateTxHash": "0x" + strings.Repeat("00", 31) + "01", "txViewingSk": "0x" + strings.Repeat("00", 31) + "41", "ephSk": "0x" + strings.Repeat("00", 31) + "02",
		"auditorPk": "0x09" + strings.Repeat("00", 31),
		"salt":      "0x" + strings.Repeat("00", 16), "nIn": 1, "nOut": 1, "inputs": openings(5), "outputs": openings(4),
		"addressChain": zeroHex(), "privateTxBlinding": zeroHex(), "sources": sources, "policyLen": 0, "ruleEnc": zeroFields(16),
		"inlineAssets": zeroFields(8), "inlineLimits": zeroFields(8), "inlineCount": 0, "limits": limits, "limitCount": 0,
		"addressTreeId": zeroHex(), "ringId": "0x" + strings.Repeat("00", 31) + "01", "namespaceOwnerHash": "0x" + strings.Repeat("00", 31) + "01", "approvalRequired": false, "keyEscrow": false,
		"memberRegistryRoot": registry.root.hex(), "foreignRoot": zeroHex(),
	}
	tree := transaction.Trees[0]
	tree.Fallback = &common.ResolvedTree{Tree: tree.Address, ID: tree.ID, UtxoRoot: state.Proofs[0].Root.hex(), NullifierRoot: exclusion.Proofs[0].Root.hex(), UtxoRootIndex: state.Proofs[0].RootIndex, NullifierRootIndex: exclusion.Proofs[0].RootIndex}
	return Request{CircuitType: common.CustomRingPolicyCircuitType, Prepared: encoded(t, prepared), Trees: []Tree{tree}, PublicInputs: zeroFields(8), Registry: registry.anchor(tree.Address)}
}

// liveOutput makes output 0 a UTXO owned by member 5 with nullifier key 6.
func liveOutput(prepared map[string]any) map[string]any {
	output := prepared["outputs"].([]any)[0].(map[string]any)
	output["domain"] = common.ToHex(big.NewInt(shared.UtxoDomain))
	output["ownerPkHash"], output["nullifierPk"] = common.ToHex(big.NewInt(5)), common.ToHex(big.NewInt(6))
	return output
}

func recordTransport(t *testing.T, calls *int, answer func(member Hash) (any, map[string]any)) roundTripFunc {
	return func(req *http.Request) (*http.Response, error) {
		*calls++
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
		if query.Method != "getRingMemberRecord" || query.Params.ExpectedNextIndex != 2 {
			t.Fatalf("registry query %s mismatch", query.Method)
		}
		result, failure := answer(query.Params.Member)
		reply := map[string]any{"jsonrpc": "2.0", "id": query.Method, "result": result}
		if failure != nil {
			reply = map[string]any{"jsonrpc": "2.0", "id": query.Method, "error": failure}
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(encoded(t, reply)))}, nil
	}
}

func newTestResolver(t *testing.T) *Resolver {
	t.Helper()
	resolver, err := NewResolver(Config{URL: "http://indexer.test", Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

// Every live slot opens its owner, a listed one by its record and an unlisted one by the low record.
func TestPolicyResolvesEveryLiveSubject(t *testing.T) {
	registry := newHostRegistry(t)
	request := policyFixture(t, registry)
	var raw map[string]any
	if err := json.Unmarshal(request.Prepared, &raw); err != nil {
		t.Fatal(err)
	}
	liveOutput(raw)
	input := raw["inputs"].([]any)[0].(map[string]any)
	input["domain"], input["ownerPkHash"] = common.ToHex(big.NewInt(shared.UtxoDomain)), common.ToHex(big.NewInt(3))
	request.Prepared = encoded(t, raw)
	calls := 0
	resolver := newTestResolver(t)
	resolver.client.Transport = recordTransport(t, &calls, func(member Hash) (any, map[string]any) {
		if member == registry.member {
			return registry.present(), nil
		}
		return registry.absent(), nil
	})
	resolved, err := resolver.Resolve(context.Background(), encoded(t, request))
	if err != nil {
		t.Fatal(err)
	}
	var params ring.PolicyParams
	if err := json.Unmarshal(resolved.Payload, &params); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || common.FeHex(params.PublicInputHash.Int) != resolved.Resolution.PublicInputHash {
		t.Fatalf("calls %d, statement %s", calls, resolved.Resolution.PublicInputHash)
	}
	sender, recipient := params.Subjects[0], params.Subjects[5]
	if sender == nil || sender.Present || sender.LowNext.Cmp(new(big.Int).SetBytes(registry.record.Next[:])) != 0 || sender.Index != 0 {
		t.Fatalf("sender opening %+v", sender)
	}
	if recipient == nil || !recipient.Present || recipient.Lists != 0b101 || recipient.Index != 1 || params.Outputs[0].CtHash.Sign() != 0 {
		t.Fatalf("recipient opening %+v", recipient)
	}
	for _, slot := range []int{1, 2, 3, 4, 6, 7, 8} {
		if params.Subjects[slot] != nil {
			t.Fatalf("dead slot %d opened", slot)
		}
	}
	for _, foreign := range params.ForeignSubjects {
		if foreign != nil {
			t.Fatal("foreign subject opened without a curator")
		}
	}
}

func TestPolicyRejectsResolvedFieldsInEveryWrapper(t *testing.T) {
	registry := newHostRegistry(t)
	for _, circuit := range []common.CircuitType{common.CustomRingPolicyCircuitType, common.CustomRingDelegatePolicyCircuitType} {
		for _, field := range []string{"subjects", "foreignSubjects", "ctHash", "foreignRoot"} {
			t.Run(string(circuit)+"/"+field, func(t *testing.T) {
				request := policyFixture(t, registry)
				var base map[string]any
				if err := json.Unmarshal(request.Prepared, &base); err != nil {
					t.Fatal(err)
				}
				switch field {
				case "ctHash":
					base["outputs"].([]any)[0].(map[string]any)["ctHash"] = zeroHex()
				case "foreignRoot":
					base["foreignRoot"] = registry.root.hex()
				default:
					base[field] = make([]any, 9)
				}
				request.CircuitType = circuit
				if circuit == common.CustomRingPolicyCircuitType {
					request.Prepared = encoded(t, base)
				} else {
					request.Prepared = encoded(t, map[string]any{"circuitType": circuit, "policy": base})
				}
				if Validate(encoded(t, request)) == nil {
					t.Fatal("resolved field accepted in a prepared policy")
				}
			})
		}
	}
}

func TestPolicyRequiresTheRegistryAnchor(t *testing.T) {
	registry := newHostRegistry(t)
	request := policyFixture(t, registry)
	request.Registry = nil
	if Validate(encoded(t, request)) == nil {
		t.Fatal("policy without a registry anchor accepted")
	}
	request.Registry = registry.anchor(request.Trees[0].Address)
	request.Registry.Root[31]++
	if Validate(encoded(t, request)) == nil {
		t.Fatal("registry anchor off the bound root accepted")
	}
	request.Registry = registry.anchor(request.Trees[0].Address)
	request.ForeignRegistry = registry.anchor(request.Trees[0].Address)
	if Validate(encoded(t, request)) == nil {
		t.Fatal("foreign anchor without a foreign root accepted")
	}
}

// A curator registry opens every live subject a second time under its own root.
func TestPolicyResolvesForeignSubjects(t *testing.T) {
	registry := newHostRegistry(t)
	request := policyFixture(t, registry)
	var raw map[string]any
	if err := json.Unmarshal(request.Prepared, &raw); err != nil {
		t.Fatal(err)
	}
	liveOutput(raw)
	raw["foreignRoot"] = registry.root.hex()
	request.Prepared = encoded(t, raw)
	request.ForeignRegistry = registry.anchor(request.Trees[0].Address)
	calls := 0
	resolver := newTestResolver(t)
	resolver.client.Transport = recordTransport(t, &calls, func(Hash) (any, map[string]any) { return registry.present(), nil })
	resolved, err := resolver.Resolve(context.Background(), encoded(t, request))
	if err != nil {
		t.Fatal(err)
	}
	var params ring.PolicyParams
	if err := json.Unmarshal(resolved.Payload, &params); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || params.ForeignSubjects[5] == nil || !params.ForeignSubjects[5].Present || params.Subjects[5] == nil {
		t.Fatalf("calls %d, foreign %+v", calls, params.ForeignSubjects[5])
	}
}

func TestPolicyRegistryBindsOwnerKeyAndAnchor(t *testing.T) {
	registry := newHostRegistry(t)
	request := policyFixture(t, registry)
	var base map[string]any
	if err := json.Unmarshal(request.Prepared, &base); err != nil {
		t.Fatal(err)
	}
	output := liveOutput(base)
	base["keyEscrow"] = true
	request.Prepared = encoded(t, base)
	for _, circuit := range []common.CircuitType{common.CustomRingPolicyCircuitType, common.CustomRingDepositCircuitType} {
		for _, mutation := range []string{"", "owner", "root", "count", "index", "path", "ciphertext", "missing ciphertext", "nullifier", "lists", "stale", "absent", "unregistered"} {
			t.Run(string(circuit)+"/"+mutation, func(t *testing.T) {
				resolver := newTestResolver(t)
				response := registry.present()
				switch mutation {
				case "owner":
					response.Record.Member[31]++
				case "root":
					response.Root[31]++
				case "count":
					response.NextIndex++
				case "index":
					response.Index = 0
				case "path":
					response.Path[1][31]++
				case "ciphertext":
					response.Record.Ciphertext[0]++
				case "missing ciphertext":
					response.Record.Ciphertext = nil
				case "lists":
					response.Record.Lists++
				case "absent":
					response = registry.absent()
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
					current.PublicInputs = []string{"0x0"}
					current.Prepared = encoded(t, map[string]any{"circuitType": circuit, "publicInputHash": common.ToHex(new(big.Int)), "contextHash": common.ToHex(new(big.Int)), "count": 1, "ownerPkHashes": column(output["ownerPkHash"]), "nullifierPks": column(output["nullifierPk"]), "blindings": column(common.ToHex(big.NewInt(1))), "keyEscrow": true, "memberRegistryRoot": base["memberRegistryRoot"], "ephSk": base["ephSk"], "auditorPk": base["auditorPk"]})
				}
				if mutation == "stale" {
					current.MinContextSlot = 1
				}
				calls := 0
				resolver.client.Transport = recordTransport(t, &calls, func(member Hash) (any, map[string]any) {
					if member != registry.member {
						t.Fatal("registry query member mismatch")
					}
					if mutation == "unregistered" {
						return nil, map[string]any{"code": -32072}
					}
					return response, nil
				})
				resolved, err := resolver.Resolve(context.Background(), encoded(t, current))
				if (err == nil) != (mutation == "") {
					t.Fatalf("unexpected registry validation result %v", err)
				}
				var unregistered *UnregisteredMemberError
				if slices.Contains([]string{"ciphertext", "nullifier", "absent", "unregistered"}, mutation) != errors.As(err, &unregistered) || (unregistered != nil && unregistered.Member != registry.member) {
					t.Fatalf("unexpected unregistered member classification %v", err)
				}
				if mutation == "stale" {
					if !errors.Is(err, ErrIndexerNotReady) {
						t.Fatalf("slot lag is not retryable %v", err)
					}
					response.Context.Slot = current.MinContextSlot
					if _, err := resolver.Resolve(context.Background(), encoded(t, current)); err != nil || calls != 2 {
						t.Fatalf("fresh membership rejected %v", err)
					}
				}
				if mutation == "" && circuit == common.CustomRingDepositCircuitType {
					var params ring.DepositParams
					if err := json.Unmarshal(resolved.Payload, &params); err != nil {
						t.Fatal(err)
					}
					if params.Members[0] == nil || params.Members[0].Index != 1 || params.CtHashes[0].Cmp(registry.ctHash) != 0 || calls != 1 || resolved.Resolution.PublicInputHash != common.FeHex(params.PublicInputHash.Int) {
						t.Fatal("unresolved deposit membership")
					}
					for _, member := range params.Members[1:] {
						if member != nil {
							t.Fatal("nonzero deposit padding")
						}
					}
				}
				if mutation == "" && circuit == common.CustomRingPolicyCircuitType {
					var params ring.PolicyParams
					if err := json.Unmarshal(resolved.Payload, &params); err != nil {
						t.Fatal(err)
					}
					if params.Subjects[5] == nil || params.Subjects[5].Index != 1 || params.Outputs[0].CtHash.Cmp(registry.ctHash) != 0 || calls != 1 {
						t.Fatal("unresolved registry key")
					}
				}
			})
		}
	}
}

func TestRegistryProjectionLagRemainsRetryable(t *testing.T) {
	for _, code := range []int{-32070, -32071, -32603} {
		resolver := newTestResolver(t)
		resolver.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(encoded(t, map[string]any{"jsonrpc": "2.0", "id": "getRingMemberRecord", "error": map[string]any{"code": code, "message": "private upstream details"}})))}, nil
		})
		_, err := resolver.rpc(context.Background(), "getRingMemberRecord", nil)
		if errors.Is(err, ErrIndexerNotReady) != (code != -32603) {
			t.Fatalf("unexpected retry classification for %d", code)
		}
		if strings.Contains(err.Error(), "private") {
			t.Fatal("upstream details leaked")
		}
	}
}

func TestPolicyResolvesMintMembershipWithoutTreatingItAsAnEscrowedOwner(t *testing.T) {
	registry := newHostRegistry(t)
	request := policyFixture(t, registry)
	var raw map[string]any
	if err := json.Unmarshal(request.Prepared, &raw); err != nil {
		t.Fatal(err)
	}
	output := liveOutput(raw)
	output["asset"] = common.ToHex(big.NewInt(3))
	raw["keyEscrow"] = true
	raw["policyLen"] = 1
	raw["ruleEnc"].([]any)[0] = common.ToHex(big.NewInt(4 + 256 + 65536))
	raw["sources"].([]any)[0].(map[string]any)["listId"] = 1
	request.Prepared = encoded(t, raw)
	calls := 0
	resolver := newTestResolver(t)
	resolver.client.Transport = recordTransport(t, &calls, func(member Hash) (any, map[string]any) {
		if member == registry.member {
			return registry.present(), nil
		}
		return registry.absent(), nil
	})
	resolved, err := resolver.Resolve(context.Background(), encoded(t, request))
	if err != nil {
		t.Fatal(err)
	}
	var params ring.PolicyParams
	if err := json.Unmarshal(resolved.Payload, &params); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(params.Subjects) != 13 || params.Subjects[9] == nil || params.Subjects[9].Present {
		t.Fatalf("mint absence not resolved, calls %d, subjects %+v", calls, params.Subjects)
	}
	if params.Outputs[0].CtHash.Cmp(registry.ctHash) != 0 {
		t.Fatal("owner escrow lost")
	}
}
