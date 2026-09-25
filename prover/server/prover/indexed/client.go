package indexed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"zolana/prover/prover/timing"
)

type Config struct {
	MaxBatchLeaves uint64
	URL            string
	APIKey         string
	Concurrency    int
}

type Resolver struct {
	maxBatchLeaves uint64
	batchReplay    batchReplay
	batchPermit    chan struct{}
	batch          batchCache
	client         *http.Client
	url            string
	apiKey         string
	permits        chan struct{}
}

func NewResolver(config Config) (*Resolver, error) {
	endpoint, err := url.Parse(config.URL)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || (endpoint.Scheme != "https" && endpoint.Scheme != "http") {
		return nil, fmt.Errorf("invalid indexer URL")
	}
	if config.Concurrency < 1 {
		return nil, fmt.Errorf("invalid indexer concurrency")
	}
	if config.MaxBatchLeaves == 0 {
		config.MaxBatchLeaves = 1_000_000
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = config.Concurrency * 2
	transport.MaxConnsPerHost = config.Concurrency * 2
	return &Resolver{
		maxBatchLeaves: config.MaxBatchLeaves,
		url:            endpoint.String(), apiKey: config.APIKey,
		permits:     make(chan struct{}, config.Concurrency),
		batchPermit: make(chan struct{}, 1),
		client: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

type proofQuery struct {
	Method string
	Tree   string
	Leaves []Hash
}

type proofParams struct {
	Tree   string `json:"treeAccount"`
	Leaves []Hash `json:"leaves"`
}

func (r *Resolver) call(ctx context.Context, query proofQuery) (json.RawMessage, error) {
	return r.rpc(ctx, query.Method, proofParams{Tree: query.Tree, Leaves: query.Leaves})
}

func (r *Resolver) rpc(ctx context.Context, method string, params any) (json.RawMessage, error) {
	finish := timing.FromContext(ctx).Start(method)
	defer finish()
	body, err := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Method  string `json:"method"`
		Params  any    `json:"params"`
	}{JSONRPC: "2.0", ID: method, Method: method, Params: params})
	if err != nil {
		return nil, fmt.Errorf("cannot encode indexer request")
	}
	endpoint, err := url.Parse(r.url)
	if err != nil {
		return nil, fmt.Errorf("invalid indexer URL")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/" + method
	if r.apiKey != "" {
		parameters := endpoint.Query()
		parameters.Set("api-key", r.apiKey)
		endpoint.RawQuery = parameters.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cannot create indexer request")
	}
	request.Header.Set("Content-Type", "application/json")
	result, err := r.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("indexer request failed")
	}
	defer result.Body.Close()
	if result.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("indexer response status %d", result.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(result.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, fmt.Errorf("invalid indexer content type")
	}
	const maxResponse = 2 << 20
	data, err := io.ReadAll(io.LimitReader(result.Body, maxResponse+1))
	if err != nil || len(data) > maxResponse {
		return nil, fmt.Errorf("invalid indexer response size")
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      string          `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if json.Unmarshal(data, &envelope) != nil || envelope.JSONRPC != "2.0" || envelope.ID != method || len(envelope.Error) != 0 || len(envelope.Result) == 0 || bytes.Equal(envelope.Result, []byte("null")) {
		return nil, fmt.Errorf("invalid indexer response")
	}
	return envelope.Result, nil
}
