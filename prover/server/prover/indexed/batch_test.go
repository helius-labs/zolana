package indexed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"zolana/prover/prover/common"
	nullifiertree "zolana/prover/prover/nullifier_tree"
	"zolana/prover/prover/transcript"
)

func batchFixture(t *testing.T) (BatchRequest, []Hash) {
	t.Helper()
	tree, err := newBatchTree(40)
	if err != nil {
		t.Fatal(err)
	}
	values := make([]*big.Int, 20)
	hashes := make([]Hash, len(values))
	for i := range values {
		values[i] = big.NewInt(int64(100 + i))
		hashes[i], err = hashField(values[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	chain, err := transcript.HashChain4(values[:10])
	if err != nil {
		t.Fatal(err)
	}
	root := tree.tree.Root.Value()
	return BatchRequest{CircuitType: common.BatchAddressAppendCircuitType, Tree: (Hash{}).String(), TreeHeight: 40, BatchSize: 10, StartIndex: 1, AnchorIndex: 1, AnchorRoot: common.FeHex(&root), HashchainHash: common.FeHex(chain)}, hashes
}

func batchIndexer(t *testing.T, values []Hash, corrupt string) *Resolver {
	t.Helper()
	resolver, err := NewResolver(Config{URL: "http://indexer.test", Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	resolver.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body struct {
			Method string `json:"method"`
			Params struct {
				Start uint64 `json:"startSeq"`
				Limit uint64 `json:"limit"`
			} `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			return nil, err
		}
		if body.Method != "getNullifierQueueElements" {
			t.Error("unexpected batch method")
		}
		page := queuePage{}
		page.Context.Slot = 10
		for seq := body.Params.Start; seq < body.Params.Start+body.Params.Limit; seq++ {
			if seq > uint64(len(values)) {
				break
			}
			page.Elements = append(page.Elements, struct {
				Seq   uint64 `json:"seq"`
				Value Hash   `json:"value"`
			}{seq, values[seq-1]})
		}
		switch corrupt {
		case "gap":
			page.Elements[0].Seq++
		case "value":
			page.Elements[0].Value[31]++
		case "short":
			page.Elements = page.Elements[:len(page.Elements)-1]
		case "stale":
			page.Context.Slot = 0
		}
		data := encoded(t, map[string]any{"jsonrpc": "2.0", "id": body.Method, "result": page})
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(data))}, nil
	})
	return resolver
}

func TestIndexedBatchSatisfiesCircuitAndReusesAnchor(t *testing.T) {
	request, values := batchFixture(t)
	resolver := batchIndexer(t, values, "")
	first, err := resolver.Resolve(context.Background(), encoded(t, request))
	if err != nil {
		t.Fatal(err)
	}
	var params nullifiertree.BatchAddressAppendParameters
	if err := json.Unmarshal(first.Payload, &params); err != nil {
		t.Fatal(err)
	}
	assignment, err := params.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	circuit := nullifiertree.InitBatchAddressTreeAppendCircuit(40, 10)
	if err := test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	request.PreviousBatches = []string{request.HashchainHash}
	request.StartIndex = 11
	chainValues := make([]*big.Int, 10)
	for i, value := range values[10:] {
		chainValues[i] = new(big.Int).SetBytes(value[:])
	}
	chain, err := transcript.HashChain4(chainValues)
	if err != nil {
		t.Fatal(err)
	}
	request.HashchainHash = common.FeHex(chain)
	second, err := resolver.Resolve(context.Background(), encoded(t, request))
	if err != nil {
		t.Fatal(err)
	}
	if second.Resolution.Batch.OldRoot != first.Resolution.Batch.NewRoot {
		t.Fatal("batch roots do not chain")
	}
	request.PreviousBatches = nil
	request.AnchorIndex = 11
	request.AnchorRoot = first.Resolution.Batch.NewRoot
	repeated, err := resolver.Resolve(context.Background(), encoded(t, request))
	if err != nil {
		t.Fatal(err)
	}
	if repeated.Resolution.Batch.NewRoot != second.Resolution.Batch.NewRoot || len(resolver.batch.tree.leaves) != 11 {
		t.Fatal("anchor replay changed batch")
	}
	if err := json.Unmarshal(repeated.Payload, &params); err != nil {
		t.Fatal(err)
	}
	assignment, err = params.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

func TestIndexedBatchRejectsUnboundQueue(t *testing.T) {
	for _, corrupt := range []string{"gap", "value", "short", "stale", "anchor", "chain"} {
		t.Run(corrupt, func(t *testing.T) {
			request, values := batchFixture(t)
			request.MinContextSlot = 10
			if corrupt == "anchor" {
				request.AnchorRoot = "0x1"
			}
			if corrupt == "chain" {
				request.HashchainHash = "0x1"
			}
			if _, err := batchIndexer(t, values, corrupt).Resolve(context.Background(), encoded(t, request)); err == nil {
				t.Fatal("invalid batch accepted")
			}
		})
	}
}

func batchChain(t *testing.T, values []Hash) string {
	t.Helper()
	fields := make([]*big.Int, len(values))
	for i, value := range values {
		fields[i] = new(big.Int).SetBytes(value[:])
	}
	chain, err := transcript.HashChain4(fields)
	if err != nil {
		t.Fatal(err)
	}
	return common.FeHex(chain)
}

func TestIndexedBatchContinuesPendingBatchesWithoutReplay(t *testing.T) {
	request, values := batchFixture(t)
	resolver := batchIndexer(t, values, "")
	transport := resolver.client.Transport
	var starts []uint64
	resolver.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		var query struct {
			Params struct {
				Start uint64 `json:"startSeq"`
			} `json:"params"`
		}
		if err := json.Unmarshal(body, &query); err != nil {
			t.Fatal(err)
		}
		starts = append(starts, query.Params.Start)
		request.Body = io.NopCloser(bytes.NewReader(body))
		return transport.RoundTrip(request)
	})
	first, err := resolver.Resolve(context.Background(), encoded(t, request))
	if err != nil {
		t.Fatal(err)
	}
	request.PreviousBatches = []string{request.HashchainHash}
	request.StartIndex = 11
	request.HashchainHash = batchChain(t, values[10:])
	if _, err := resolver.Resolve(context.Background(), encoded(t, request)); err != nil {
		t.Fatal(err)
	}
	if len(starts) != 2 || starts[0] != 1 || starts[1] != 11 {
		t.Fatalf("replayed pending prefix %v", starts)
	}
	request.PreviousBatches = nil
	request.AnchorIndex, request.AnchorRoot = 11, first.Resolution.Batch.NewRoot
	if _, err := resolver.Resolve(context.Background(), encoded(t, request)); err != nil {
		t.Fatal(err)
	}
}

func TestIndexedBatchRecoversAfterAnchorReorg(t *testing.T) {
	request, values := batchFixture(t)
	resolver := batchIndexer(t, values, "")
	first, err := resolver.Resolve(context.Background(), encoded(t, request))
	if err != nil {
		t.Fatal(err)
	}
	request.AnchorIndex, request.StartIndex, request.AnchorRoot = 11, 11, first.Resolution.Batch.NewRoot
	request.HashchainHash = batchChain(t, values[10:])
	if _, err := resolver.Resolve(context.Background(), encoded(t, request)); err != nil {
		t.Fatal(err)
	}
	values[0], _ = hashField(big.NewInt(500))
	rebuilt, err := newBatchTree(40)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values[:10] {
		if err := rebuilt.append(new(big.Int).SetBytes(value[:]), nil); err != nil {
			t.Fatal(err)
		}
	}
	root := rebuilt.tree.Root.Value()
	request.AnchorRoot = common.FeHex(&root)
	if _, err := resolver.Resolve(context.Background(), encoded(t, request)); !errors.Is(err, ErrIndexerNotReady) {
		t.Fatalf("expected recoverable reorg, got %v", err)
	}
	recovered, err := resolver.Resolve(context.Background(), encoded(t, request))
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Resolution.Batch.OldRoot != request.AnchorRoot {
		t.Fatal("recovery retained the old branch")
	}
}

func TestIndexedBatchBoundsReplayAndRetriesLag(t *testing.T) {
	request, values := batchFixture(t)
	resolver := batchIndexer(t, values, "short")
	if _, err := resolver.Resolve(context.Background(), encoded(t, request)); !errors.Is(err, ErrIndexerNotReady) {
		t.Fatalf("expected recoverable lag, got %v", err)
	}
	resolver.maxBatchLeaves = 10
	resolver.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("oversized replay reached indexer")
		return nil, nil
	})
	if _, err := resolver.Resolve(context.Background(), encoded(t, request)); err == nil {
		t.Fatal("accepted replay beyond configured memory bound")
	}
}

func TestIndexedBatchReorgInvalidatesPendingPrefix(t *testing.T) {
	request, values := batchFixture(t)
	resolver := batchIndexer(t, values, "")
	if _, err := resolver.Resolve(context.Background(), encoded(t, request)); err != nil {
		t.Fatal(err)
	}
	values[0], _ = hashField(big.NewInt(500))
	request.PreviousBatches = []string{batchChain(t, values[:10])}
	request.StartIndex = 11
	request.HashchainHash = batchChain(t, values[10:])
	resolved, err := resolver.Resolve(context.Background(), encoded(t, request))
	if err != nil {
		t.Fatal(err)
	}
	expected := batchIndexer(t, values, "")
	fresh, err := expected.Resolve(context.Background(), encoded(t, request))
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Resolution.Batch.OldRoot != fresh.Resolution.Batch.OldRoot {
		t.Fatal("pending root retained stale queue prefix")
	}
	request.PreviousBatches[0] = "0x1"
	if _, err := resolver.Resolve(context.Background(), encoded(t, request)); !errors.Is(err, ErrIndexerNotReady) {
		t.Fatalf("unbound prefix accepted, got %v", err)
	}
}

func TestIndexedBatchResumesAfterCancelledRequest(t *testing.T) {
	request, _ := batchFixture(t)
	values := make([]Hash, 1010)
	tree, err := newBatchTree(40)
	if err != nil {
		t.Fatal(err)
	}
	for i := range values {
		value := big.NewInt(int64(100 + i))
		values[i], _ = hashField(value)
		if i < 1000 {
			if err := tree.append(value, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	root := tree.tree.Root.Value()
	request.AnchorIndex, request.StartIndex, request.AnchorRoot = 1001, 1001, common.FeHex(&root)
	request.HashchainHash = batchChain(t, values[1000:])
	resolver := batchIndexer(t, values, "")
	transport := resolver.client.Transport
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	resolver.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if calls == 2 {
			cancel()
			return nil, ctx.Err()
		}
		return transport.RoundTrip(request)
	})
	if _, err := resolver.Resolve(ctx, encoded(t, request)); err == nil {
		t.Fatal("cancelled request succeeded")
	}
	if resolver.batch.tree == nil || len(resolver.batch.tree.leaves) != 1001 {
		t.Fatal("validated replay was discarded")
	}
	resolver.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		var query struct {
			Params struct {
				Start uint64 `json:"startSeq"`
			} `json:"params"`
		}
		if err := json.Unmarshal(body, &query); err != nil {
			t.Fatal(err)
		}
		if query.Params.Start != 1001 {
			t.Fatal("retry replayed acknowledged prefix")
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		return transport.RoundTrip(request)
	})
	if _, err := resolver.Resolve(context.Background(), encoded(t, request)); err != nil {
		t.Fatal(err)
	}
}

func TestIndexedBatchTimeoutClassification(t *testing.T) {
	request, values := batchFixture(t)
	t.Run("lock", func(t *testing.T) {
		resolver := batchIndexer(t, values, "")
		resolver.batchLock <- struct{}{}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if _, err := resolver.Resolve(ctx, encoded(t, request)); !errors.Is(err, ErrIndexerNotReady) {
			t.Fatalf("waiting for the replay lock returned %v", err)
		}
	})
	t.Run("checkpoint", func(t *testing.T) {
		request, _ := batchFixture(t)
		values := make([]Hash, 110)
		tree, err := newBatchTree(40)
		if err != nil {
			t.Fatal(err)
		}
		for i := range values {
			value := big.NewInt(int64(100 + i))
			values[i], _ = hashField(value)
			if i < 100 {
				if err := tree.append(value, nil); err != nil {
					t.Fatal(err)
				}
			}
		}
		root := tree.tree.Root.Value()
		request.AnchorIndex, request.StartIndex, request.AnchorRoot = 101, 101, common.FeHex(&root)
		request.HashchainHash = batchChain(t, values[100:])
		resolver := batchIndexer(t, values, "")
		transport := resolver.client.Transport
		calls := 0
		resolver.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			if calls == 2 {
				<-request.Context().Done()
				return nil, request.Context().Err()
			}
			return transport.RoundTrip(request)
		})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := resolver.Resolve(ctx, encoded(t, request)); !errors.Is(err, ErrIndexerNotReady) {
			t.Fatalf("timeout after a checkpoint returned %v", err)
		}
	})
	t.Run("no progress", func(t *testing.T) {
		resolver := batchIndexer(t, values, "")
		resolver.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			<-request.Context().Done()
			return nil, request.Context().Err()
		})
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if _, err := resolver.Resolve(ctx, encoded(t, request)); err == nil || errors.Is(err, ErrIndexerNotReady) {
			t.Fatalf("timeout without progress returned %v", err)
		}
	})
}
