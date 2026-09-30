package indexed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"zolana/prover/prover/common"
	transfer "zolana/prover/prover/transfer_eddsa_only"
)

func cachedRequest(t *testing.T, request Request) Request {
	t.Helper()
	var prepared transfer.TransferParametersJSON
	if err := json.Unmarshal(request.Prepared, &prepared); err != nil {
		t.Fatal(err)
	}
	prepared.CacheSelectionJSON = transfer.CacheSelectionJSON{
		CacheReadHashes: []string{"0x2a", "0x0"},
		CacheIsCached:   []string{"0x1", "0x0"},
		CacheReadIndex:  []string{"0x0", "0x0"},
	}
	request.Prepared = encoded(t, prepared)
	request.Inputs[0].Commitment = nil
	return request
}

func TestCachedInputsFetchOnlyNullifierProofs(t *testing.T) {
	request, _, nullifiers := fixture(t)
	request = cachedRequest(t, request)
	resolver, err := NewResolver(Config{URL: "http://indexer.test", Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	resolver.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body struct {
			Method string      `json:"method"`
			Params proofParams `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return nil, err
		}
		calls++
		if body.Method != "getNonInclusionProofs" || len(body.Params.Leaves) != 2 {
			t.Errorf("unexpected indexer request %s", body.Method)
		}
		data := encoded(t, map[string]any{"jsonrpc": "2.0", "id": body.Method, "result": nullifiers})
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(data))}, nil
	})
	resolved, err := resolver.Resolve(context.Background(), encoded(t, request))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || resolved.Resolution.Trees[0].UtxoRootIndex != 65535 || resolved.Resolution.Trees[0].UtxoRoot != (Hash{}).hex() {
		t.Fatal("cached state root was not omitted")
	}
	var complete transfer.TransferParameters
	if err := json.Unmarshal(resolved.Payload, &complete); err != nil {
		t.Fatal(err)
	}
	for _, input := range complete.Inputs {
		if len(input.NullifierLowPathElements) != 40 || len(input.StatePathElements) != 32 {
			t.Fatal("incomplete cached input")
		}
		for _, node := range input.StatePathElements {
			if node.Sign() != 0 {
				t.Fatal("cached input contains a state path")
			}
		}
	}
}

func TestRejectInvalidCachedLookups(t *testing.T) {
	for _, corruption := range []string{"missing flag", "nonbit", "short", "dummy", "authority", "commitment", "empty entry"} {
		t.Run(corruption, func(t *testing.T) {
			request, state, _ := fixture(t)
			request = cachedRequest(t, request)
			var prepared transfer.TransferParametersJSON
			if err := json.Unmarshal(request.Prepared, &prepared); err != nil {
				t.Fatal(err)
			}
			switch corruption {
			case "missing flag":
				prepared.CacheIsCached = nil
			case "nonbit":
				prepared.CacheIsCached[0] = "0x2"
			case "short":
				prepared.CacheIsCached = prepared.CacheIsCached[:1]
			case "dummy":
				prepared.CacheIsCached[1] = "0x1"
			case "authority":
				request.CircuitType = common.TransferRingAuthorityCircuitType
				prepared.CircuitType = request.CircuitType
				request.PublicInputs = request.PublicInputs[:14]
			case "commitment":
				request.Inputs[0].Commitment = &state.Proofs[0].Leaf
			case "empty entry":
				prepared.CacheReadHashes[0] = "0x0"
			}
			request.Prepared = encoded(t, prepared)
			if Validate(encoded(t, request)) == nil {
				t.Fatal("invalid cache request accepted")
			}
		})
	}
}

func TestMixedCacheLookupsKeepEachTreeRoot(t *testing.T) {
	for _, separate := range []bool{false, true} {
		t.Run(fmt.Sprint(separate), func(t *testing.T) {
			request, state, nullifiers := fixture(t)
			request = cachedRequest(t, request)
			var prepared transfer.TransferParametersJSON
			if err := json.Unmarshal(request.Prepared, &prepared); err != nil {
				t.Fatal(err)
			}
			prepared.Inputs[1].IsDummy = "0x0"
			request.Inputs[1].Commitment = &state.Proofs[0].Leaf
			if separate {
				other := Hash{31: 1}.String()
				request.Trees = append(request.Trees, Tree{Address: other, ID: 1})
				request.Inputs[1].TreeSlot = 1
				prepared.Inputs[1].TreeSlot = "0x1"
			}
			request.Prepared = encoded(t, prepared)
			resolver, err := NewResolver(Config{URL: "http://indexer.test", Concurrency: 1})
			if err != nil {
				t.Fatal(err)
			}
			var stateCalls atomic.Int32
			resolver.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				var body struct {
					Method string      `json:"method"`
					Params proofParams `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					return nil, err
				}
				var result any
				if body.Method == "getMerkleProofs" {
					stateCalls.Add(1)
					if len(body.Params.Leaves) != 1 || (separate && body.Params.Tree == request.Trees[0].Address) {
						t.Error("cached commitment fetched")
					}
					proof := state.Proofs[0]
					proof.MerkleContext.Tree = body.Params.Tree
					result = response[stateProof]{Context: state.Context, Proofs: []stateProof{proof}}
				} else {
					proofs := make([]nullifierProof, 0, len(body.Params.Leaves))
					for _, leaf := range body.Params.Leaves {
						for _, proof := range nullifiers.Proofs {
							if proof.Leaf == leaf {
								proof.MerkleContext.Tree = body.Params.Tree
								proofs = append(proofs, proof)
							}
						}
					}
					result = response[nullifierProof]{Context: nullifiers.Context, Proofs: proofs}
				}
				data := encoded(t, map[string]any{"jsonrpc": "2.0", "id": body.Method, "result": result})
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(data))}, nil
			})
			resolved, err := resolver.Resolve(context.Background(), encoded(t, request))
			if err != nil {
				t.Fatal(err)
			}
			if stateCalls.Load() != 1 {
				t.Fatal("unexpected state fetch count")
			}
			for index, tree := range resolved.Resolution.Trees {
				if separate && index == 0 {
					if tree.UtxoRootIndex != 65535 || tree.UtxoRoot != (Hash{}).hex() {
						t.Fatal("cached tree has state root")
					}
				} else if tree.UtxoRootIndex != state.Proofs[0].RootIndex || tree.UtxoRoot != state.Proofs[0].Root.hex() {
					t.Fatal("uncached tree lost state root")
				}
			}
		})
	}
}
