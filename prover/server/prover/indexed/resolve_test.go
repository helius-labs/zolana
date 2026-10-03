package indexed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"zolana/prover/prover/common"
	prooftranscript "zolana/prover/prover/transcript"
	transfer "zolana/prover/prover/transfer_eddsa_only"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func fixture(t *testing.T) (Request, response[stateProof], response[nullifierProof]) {
	t.Helper()
	toHash := func(value int64) Hash {
		hash, err := hashField(big.NewInt(value))
		if err != nil {
			t.Fatal(err)
		}
		return hash
	}
	root := func(leaf Hash, height int) Hash {
		hash := new(big.Int).SetBytes(leaf[:])
		for range height {
			var err error
			hash, err = prooftranscript.HashFields([]*big.Int{hash, new(big.Int)})
			if err != nil {
				t.Fatal(err)
			}
		}
		result, err := hashField(hash)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	commitment := toHash(42)
	tree := (Hash{}).String()
	prepared, err := json.Marshal(transfer.TransferParametersJSON{
		CircuitType: common.TransferConfidentialCircuitType,
		NInputs:     2, NOutputs: 2, BlindingSeed: "0x1",
		PublicAssets: []string{"0x0", "0x0", "0x0"}, PublicAmounts: []string{"0x0", "0x0", "0x0"},
		Inputs:  []transfer.InputParamsJSON{{IsDummy: "0x0", Nullifier: "0x64"}, {IsDummy: "0x1", Nullifier: "0xc8"}},
		Outputs: []transfer.OutputParamsJSON{{}, {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := Request{
		CircuitType: common.TransferConfidentialCircuitType, Prepared: prepared,
		Trees:        []Tree{{Address: tree, ID: 0}},
		Inputs:       []Lookup{{TreeSlot: 0, Commitment: &commitment}, {TreeSlot: 0}},
		PublicInputs: make([]string, 17), MinContextSlot: 10,
	}
	for index := range request.PublicInputs {
		request.PublicInputs[index] = "0x0"
	}
	state := response[stateProof]{Proofs: []stateProof{{
		Leaf: commitment, MerkleContext: merkleContext{Tree: tree, TreeType: 1},
		Path: make([]Hash, 32), Root: root(commitment, 32), RootIndex: 3,
	}}}
	state.Context.Slot = 10
	low, high := toHash(0), toHash(1000)
	leaf, err := prooftranscript.HashFields([]*big.Int{big.NewInt(0), big.NewInt(1000)})
	if err != nil {
		t.Fatal(err)
	}
	leafHash, err := hashField(leaf)
	if err != nil {
		t.Fatal(err)
	}
	nullifier := response[nullifierProof]{Proofs: []nullifierProof{}}
	nullifier.Context.Slot = 10
	for _, value := range []int64{100, 200} {
		nullifier.Proofs = append(nullifier.Proofs, nullifierProof{
			Leaf: toHash(value), MerkleContext: merkleContext{Tree: tree, TreeType: 2},
			Path: make([]Hash, 40), LowElement: low, HighElement: high,
			Root: root(leafHash, 40), RootIndex: 4,
		})
	}
	return request, state, nullifier
}

func encoded(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestResolveFetchesParallelProofsAndBindsDummyRoot(t *testing.T) {
	request, state, nullifier := fixture(t)
	ready := make(chan struct{})
	var mutex sync.Mutex
	calls := make(map[string][]Hash)
	resolver, err := NewResolver(Config{URL: "http://indexer.test", Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	resolver.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body struct {
			Method string      `json:"method"`
			Params proofParams `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			return nil, err
		}
		mutex.Lock()
		calls[body.Method] = body.Params.Leaves
		if len(calls) == 2 {
			close(ready)
		}
		mutex.Unlock()
		select {
		case <-ready:
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
		var result any = state
		if body.Method == "getNonInclusionProofs" {
			result = nullifier
		}
		data, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": body.Method, "result": result})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(data))}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resolved, err := resolver.Resolve(ctx, encoded(t, request))
	if err != nil {
		t.Fatal(err)
	}
	if len(calls["getMerkleProofs"]) != 1 || len(calls["getNonInclusionProofs"]) != 2 {
		t.Fatal("real and dummy nullifiers were not fetched together")
	}
	var value transfer.TransferParameters
	if err := json.Unmarshal(resolved.Payload, &value); err != nil {
		t.Fatal(err)
	}
	if len(value.Inputs[0].StatePathElements) != 32 || len(value.Inputs[1].NullifierLowPathElements) != 40 || len(value.TreeSlots) != 5 {
		t.Fatal("resolved paths are incomplete")
	}
	if value.TreeSlots[0].NullifierRoot.Cmp(new(big.Int).SetBytes(nullifier.Proofs[0].Root[:])) != 0 || resolved.Resolution.Trees[0].UtxoRootIndex != 3 {
		t.Fatal("resolved roots differ from the indexer snapshot")
	}
	if common.FeHex(value.PublicInputHash) != resolved.Resolution.PublicInputHash {
		t.Fatal("response hash differs from the proved input")
	}
}

// Compact padding publishes nullifier 0 but proves non-inclusion of its derived
// dummy nullifier, which the lookup carries: the resolver fetches that witness
// and fills the slot with it while the published value stays 0.
func TestResolveFetchesCompactPaddingByLookupNullifier(t *testing.T) {
	request, state, nullifier := fixture(t)
	var prepared transfer.TransferParametersJSON
	if err := json.Unmarshal(request.Prepared, &prepared); err != nil {
		t.Fatal(err)
	}
	prepared.Inputs[1].Nullifier = "0x0"
	request.Prepared = encoded(t, prepared)
	derived, err := hashField(big.NewInt(200))
	if err != nil {
		t.Fatal(err)
	}
	request.Inputs[1].Nullifier = &derived
	var fetched []Hash
	resolver, err := NewResolver(Config{URL: "http://indexer.test", Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	resolver.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body struct {
			Method string      `json:"method"`
			Params proofParams `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			return nil, err
		}
		var result any = state
		if body.Method == "getNonInclusionProofs" {
			fetched = body.Params.Leaves
			result = nullifier
		}
		data, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": body.Method, "result": result})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(data))}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resolved, err := resolver.Resolve(ctx, encoded(t, request))
	if err != nil {
		t.Fatal(err)
	}
	if len(fetched) != 2 || fetched[1] != derived {
		t.Fatalf("fetched %v, want the compact slot's derived nullifier %v", fetched, derived)
	}
	var value transfer.TransferParameters
	if err := json.Unmarshal(resolved.Payload, &value); err != nil {
		t.Fatal(err)
	}
	compact := value.Inputs[1]
	if compact.Nullifier.Sign() != 0 {
		t.Fatalf("published nullifier %v, want 0", compact.Nullifier)
	}
	if compact.NullifierLowValue.Sign() != 0 || compact.NullifierNextValue.Cmp(big.NewInt(1000)) != 0 || len(compact.NullifierLowPathElements) != 40 {
		t.Fatal("compact padding witness is not the fetched exclusion range")
	}
}

// A compact slot is the only input that carries a lookup nullifier, and it
// must carry one.
func TestResolveRejectsCompactPaddingLookupMismatch(t *testing.T) {
	request, _, _ := fixture(t)
	var prepared transfer.TransferParametersJSON
	if err := json.Unmarshal(request.Prepared, &prepared); err != nil {
		t.Fatal(err)
	}
	derived, err := hashField(big.NewInt(200))
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewResolver(Config{URL: "http://indexer.test", Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	for name, corrupt := range map[string]func(){
		"compact without lookup": func() { prepared.Inputs[1].Nullifier = "0x0" },
		"lookup without compact": func() { request.Inputs[1].Nullifier = &derived },
	} {
		t.Run(name, func(t *testing.T) {
			request, prepared := request, prepared
			corrupt()
			request.Prepared = encoded(t, prepared)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := resolver.Resolve(ctx, encoded(t, request))
			if err == nil || !strings.Contains(err.Error(), "input lookup mismatch") {
				t.Fatalf("got %v, want input lookup mismatch", err)
			}
			prepared.Inputs[1].Nullifier = "0xc8"
			request.Inputs[1].Nullifier = nil
		})
	}
}

// Only a dummy that publishes nullifier 0 is compact padding. A real input
// that claims 0 is still fetched, and no exclusion range can hold below 0, so
// even an indexer that answers for leaf 0 cannot make the resolver accept it.
func TestResolveRejectsRealInputWithZeroNullifier(t *testing.T) {
	request, state, nullifier := fixture(t)
	var prepared transfer.TransferParametersJSON
	if err := json.Unmarshal(request.Prepared, &prepared); err != nil {
		t.Fatal(err)
	}
	prepared.Inputs[0].Nullifier = "0x0"
	request.Prepared = encoded(t, prepared)
	nullifier.Proofs[0].Leaf = Hash{}
	var fetched []Hash
	resolver, err := NewResolver(Config{URL: "http://indexer.test", Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	resolver.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body struct {
			Method string      `json:"method"`
			Params proofParams `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			return nil, err
		}
		var result any = state
		if body.Method == "getNonInclusionProofs" {
			fetched = body.Params.Leaves
			result = nullifier
		}
		data, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": body.Method, "result": result})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(data))}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = resolver.Resolve(ctx, encoded(t, request))
	if err == nil || !strings.Contains(err.Error(), "invalid nullifier exclusion range") {
		t.Fatalf("got %v, want the exclusion range to reject nullifier 0", err)
	}
	if len(fetched) != 2 || fetched[0] != (Hash{}) {
		t.Fatalf("fetched %v, want the real input's zero nullifier requested, not skipped", fetched)
	}
}

func TestResolveRejectsUnboundAndStaleProofs(t *testing.T) {
	for _, corruption := range []string{"leaf", "path", "tree", "root", "count", "stale"} {
		t.Run(corruption, func(t *testing.T) {
			request, state, nullifier := fixture(t)
			switch corruption {
			case "leaf":
				nullifier.Proofs[1].Leaf = Hash{}
			case "path":
				state.Proofs[0].Path[0][31] = 1
			case "tree":
				state.Proofs[0].MerkleContext.Tree = "wrong"
			case "root":
				nullifier.Proofs[1].RootIndex++
			case "count":
				nullifier.Proofs = nullifier.Proofs[:1]
			case "stale":
				state.Context.Slot = 9
			}
			resolver := &Resolver{url: "http://indexer.test", permits: make(chan struct{}, 1), client: &http.Client{}}
			resolver.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				var body struct{ Method string }
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					return nil, err
				}
				var result any = state
				if body.Method == "getNonInclusionProofs" {
					result = nullifier
				}
				data, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": body.Method, "result": result})
				if err != nil {
					return nil, err
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(data))}, nil
			})
			_, err := resolver.Resolve(context.Background(), encoded(t, request))
			if err == nil {
				t.Fatal("invalid indexer data was accepted")
			}
			if errors.Is(err, ErrIndexerNotReady) != (corruption == "stale") {
				t.Fatalf("unexpected retry classification %v", err)
			}
			if len(resolver.permits) != 0 {
				t.Fatal("failed resolution retained a permit")
			}
		})
	}
}

func TestValidateRejectsMalformedPreparedRequests(t *testing.T) {
	for _, corruption := range []string{"shape", "count", "circuit", "tree", "field", "paths", "slot", "dummy"} {
		t.Run(corruption, func(t *testing.T) {
			request, _, _ := fixture(t)
			var prepared transfer.TransferParametersJSON
			if err := json.Unmarshal(request.Prepared, &prepared); err != nil {
				t.Fatal(err)
			}
			switch corruption {
			case "shape":
				prepared.NOutputs = 1
				prepared.Outputs = prepared.Outputs[:1]
			case "count":
				prepared.NInputs = 1
			case "circuit":
				request.CircuitType = common.MergeCircuitType
			case "tree":
				request.Trees[0].Address = "invalid"
			case "field":
				request.PublicInputs[0] = "-1"
			case "paths":
				prepared.Inputs[0].StatePathElements = []string{"0x0"}
			case "slot":
				request.Inputs[0].TreeSlot = 1
			case "dummy":
				request.Inputs[0].Commitment = nil
			}
			request.Prepared = encoded(t, prepared)
			if err := Validate(encoded(t, request)); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestResolveCancellationReleasesPreparation(t *testing.T) {
	request, _, _ := fixture(t)
	resolver, err := NewResolver(Config{URL: "http://indexer.test", Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	var calls sync.WaitGroup
	calls.Add(2)
	resolver.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Done()
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	data := encoded(t, request)
	go func() { _, err := resolver.Resolve(ctx, data); done <- err }()
	calls.Wait()
	cancel()
	select {
	case err := <-done:
		if err == nil || len(resolver.permits) != 0 {
			t.Fatal("canceled resolution retained work")
		}
	case <-time.After(time.Second):
		t.Fatal("resolution ignored cancellation")
	}
}
