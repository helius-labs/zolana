package transaction

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	backendwitness "github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	gtest "github.com/consensys/gnark/test"
	custom "zolana/prover/circuits/spp_transaction/custom"
	shared "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover/common"
	"zolana/prover/prover/indexed"
	transfer "zolana/prover/prover/transfer_eddsa_only"
	"zolana/prover/server"
)

type latencyFixture struct {
	Request    indexed.Request
	Params     transfer.TransferParameters
	State      map[string]any
	Nullifiers map[string]any
}

type latencySample struct {
	Proof       *common.Proof `json:"-"`
	TotalMS     float64       `json:"total_ms"`
	FetchMS     float64       `json:"fetch_ms"`
	ProofHTTPMS float64       `json:"proof_http_ms"`
	Status      int           `json:"status"`
	Verified    bool          `json:"verified"`
}

type latencyResult struct {
	RTTMS       int              `json:"rtt_ms"`
	Repeat      int              `json:"repeat"`
	Calibration []float64        `json:"calibration_ms"`
	Environment benchEnvironment `json:"environment"`
	Profile     string           `json:"cpu_profile,omitempty"`
	CPUSeconds  float64          `json:"cpu_seconds"`
	PeakRSS     uint64           `json:"process_peak_rss_bytes"`
	Mode        string           `json:"mode"`
	Workers     int              `json:"workers"`
	Clients     int              `json:"clients"`
	Samples     []latencySample  `json:"samples"`
	Seconds     float64          `json:"seconds"`
	TPS         float64          `json:"proofs_per_second"`
	P50         float64          `json:"p50_ms"`
	P95         float64          `json:"p95_ms"`
	Failures    int              `json:"failures"`
}

func benchField(value frontend.Variable) *big.Int {
	switch value := value.(type) {
	case *big.Int:
		return new(big.Int).Set(value)
	case int:
		return big.NewInt(int64(value))
	case uint64:
		return new(big.Int).SetUint64(value)
	default:
		panic(fmt.Sprintf("unexpected fixture field %T", value))
	}
}
func benchFields(values []frontend.Variable) []*big.Int {
	out := make([]*big.Int, len(values))
	for i, value := range values {
		out[i] = benchField(value)
	}
	return out
}
func benchHash(value *big.Int) indexed.Hash {
	var hash indexed.Hash
	value.FillBytes(hash[:])
	return hash
}
func benchHashes(values []*big.Int) []indexed.Hash {
	out := make([]indexed.Hash, len(values))
	for i, value := range values {
		out[i] = benchHash(value)
	}
	return out
}
func benchUTXO(value shared.UtxoCircuitFields) transfer.UtxoParams {
	return transfer.UtxoParams{Domain: benchField(value.Domain), Owner: benchField(value.Owner), Asset: benchField(value.Asset), Amount: benchField(value.Amount), Blinding: benchField(value.Blinding), DataHash: benchField(value.DataHash), RingDataHash: benchField(value.RingDataHash), RingProgramID: benchField(value.RingProgramID)}
}
func benchEncode(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func makeLatencyFixture(t *testing.T, serial int) latencyFixture {
	t.Helper()
	shape := protocol.Shape{NInputs: 2, NOutputs: 3}
	tx, payer, err := benchmarkTransaction(shape)
	if err != nil {
		t.Fatal(err)
	}
	for i := range tx.Inputs {
		tx.Inputs[i].Utxo.Blinding = fmt.Sprintf("0x%x", 1000+serial*2+i)
		utxo := protocol.Utxo{Domain: big.NewInt(protocol.UtxoDomain), Owner: new(big.Int), Asset: protocol.SolAsset(), Amount: big.NewInt(30), Blinding: big.NewInt(int64(1000 + serial*2 + i)), DataHash: new(big.Int), RingDataHash: new(big.Int), RingProgramID: new(big.Int)}
		pk, _ := protocol.NullifierPk(big.NewInt(12345))
		utxo.Owner, _ = protocol.OwnerHash(payer, pk)
		hash, err := protocol.UtxoHash(utxo, big.NewInt(0))
		if err != nil {
			t.Fatal(err)
		}
		tx.StateEntries[i].Hash = common.FeHex(hash)
	}
	built, err := buildProofAssignment(shape, tx, payer, proofBuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	witness := built.witness.(*custom.CustomRingEddsaOnlyCircuit)
	public := built.publicInputs
	// 1. The default confidential statement binds a zero ring program.
	public.RingProgramID = new(big.Int)
	built.publicInputHash, err = protocol.PublicInputHash(public)
	if err != nil {
		t.Fatal(err)
	}
	p := transfer.TransferParameters{Variant: transfer.ConfidentialVariant, NInputs: 2, NOutputs: 3,
		OutputTreeID: public.OutputTreeID, ExternalDataHash: public.ExternalDataHash, PrivateTxHash: public.PrivateTxHash,
		BlindingSeed: benchField(witness.Private.BlindingSeed), PublicAssets: public.PublicAssets[:], PublicAmounts: public.PublicAmounts[:],
		RingProgramID: public.RingProgramID, SignerPkHashes: public.SignerPkHashes, InputFlags: public.InputFlags,
		PublishedOutputOwnerPkHashes: public.OutputOwnerPkHashes, PublicInputHash: built.publicInputHash}
	for _, slot := range public.TreeSlots {
		p.TreeSlots = append(p.TreeSlots, common.TreeSlotParams{ID: slot.ID, UtxoRoot: slot.UtxoRoot, NullifierRoot: slot.NullifierRoot})
	}
	for i, input := range witness.Private.Inputs {
		p.Inputs = append(p.Inputs, transfer.InputParams{Utxo: benchUTXO(input.Utxo), IsDummy: new(big.Int),
			StatePathElements: benchFields(input.StatePathElements), StatePathIndex: benchField(input.StatePathIndex),
			NullifierLowValue: benchField(input.NullifierLowValue), NullifierNextValue: benchField(input.NullifierNextValue),
			NullifierLowPathElements: benchFields(input.NullifierLowPathElements), NullifierLowPathIndex: benchField(input.NullifierLowPathIndex),
			TreeSlot: benchField(input.TreeSlot), Nullifier: public.Nullifiers[i], OwnerPkHash: benchField(witness.Private.InputOwnerPkHashes[i]), NullifierSecret: benchField(input.NullifierSecret)})
	}
	for i, output := range witness.Private.Outputs {
		p.Outputs = append(p.Outputs, transfer.OutputParams{Utxo: benchUTXO(output), IsDummy: new(big.Int), Hash: public.OutputUtxoHashes[i], OwnerPkHash: benchField(witness.Private.OutputOwnerPkHashes[i]), NullifierPk: benchField(witness.Private.OutputNullifierPks[i])})
	}
	var prepared map[string]any
	if err := json.Unmarshal(benchEncode(t, &p), &prepared); err != nil {
		t.Fatal(err)
	}
	delete(prepared, "treeSlots")
	delete(prepared, "publicInputHash")
	for _, item := range prepared["inputs"].([]any) {
		for _, field := range []string{"statePathElements", "statePathIndex", "nullifierLowValue", "nullifierNextValue", "nullifierLowPathElements", "nullifierLowPathIndex"} {
			delete(item.(map[string]any), field)
		}
	}
	chain := func(values []*big.Int) *big.Int {
		v, err := common.HashChain4(values)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	signers, err := common.RightHashChain(public.SignerPkHashes)
	if err != nil {
		t.Fatal(err)
	}
	fields := []*big.Int{chain(public.Nullifiers), chain(public.OutputUtxoHashes), public.OutputTreeID, public.PrivateTxHash, public.ExternalDataHash}
	for i := range public.PublicAssets {
		fields = append(fields, public.PublicAssets[i], public.PublicAmounts[i])
	}
	fields = append(fields, public.RingProgramID, signers, public.InputFlags, chain(public.OutputOwnerPkHashes))
	tree := (indexed.Hash{}).String()
	fixture := latencyFixture{Params: p, State: map[string]any{}, Nullifiers: map[string]any{}}
	fixture.Request = indexed.Request{CircuitType: common.TransferConfidentialCircuitType, Prepared: benchEncode(t, prepared), Trees: []indexed.Tree{{Address: tree, ID: 0}}, PublicInputs: common.FeHexSlice(fields)}
	for i, input := range p.Inputs {
		hash := benchHash(built.transcript.inputHashes[i])
		fixture.Request.Inputs = append(fixture.Request.Inputs, indexed.Lookup{TreeSlot: 0, Commitment: &hash})
		fixture.State[hash.String()] = map[string]any{"leaf": hash, "merkleContext": map[string]any{"tree": tree, "treeType": 1}, "path": benchHashes(input.StatePathElements), "leafIndex": input.StatePathIndex.Uint64(), "root": benchHash(p.TreeSlots[0].UtxoRoot), "rootIndex": 0, "rootSeq": 0}
		nullifier := benchHash(input.Nullifier)
		fixture.Nullifiers[nullifier.String()] = map[string]any{"leaf": nullifier, "merkleContext": map[string]any{"tree": tree, "treeType": 2}, "path": benchHashes(input.NullifierLowPathElements), "lowElement": benchHash(input.NullifierLowValue), "highElement": benchHash(input.NullifierNextValue), "lowElementIndex": input.NullifierLowPathIndex.Uint64(), "highElementIndex": 0, "root": benchHash(p.TreeSlots[0].NullifierRoot), "rootIndex": 0, "rootSeq": 0}
	}
	return fixture
}

type delayTransport struct {
	base  http.RoundTripper
	delay time.Duration
}

func (d delayTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := d.base.RoundTrip(request)
	time.Sleep(d.delay)
	return response, err
}
func delayedEndpoint(target string, rtt time.Duration) *httptest.Server {
	endpoint, _ := url.Parse(target)
	proxy := httputil.NewSingleHostReverseProxy(endpoint)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 64
	proxy.Transport = delayTransport{base: transport, delay: rtt / 2}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(rtt / 2); proxy.ServeHTTP(w, r) }))
}
func unusedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

func TestProofNetworkBenchmark(t *testing.T) {
	if os.Getenv("PROVER_NETWORK_BENCH") != "1" {
		t.Skip("explicit benchmark opt in required")
	}
	options := readBenchOptions(t)
	var results []latencyResult
	for repeat := 1; repeat <= options.repeats; repeat++ {
		for _, rtt := range options.rtts {
			t.Run(fmt.Sprintf("repeat_%d_rtt_%d", repeat, rtt), func(t *testing.T) {
				runNetworkBenchmark(t, options, repeat, rtt, &results)
			})
		}
	}
}

func runNetworkBenchmark(t *testing.T, options benchOptions, repeat, rtt int, results *[]latencyResult) {
	fixtures := make([]latencyFixture, max(options.requests, options.maxClients()))
	state := map[string]any{}
	nullifiers := map[string]any{}
	for i := range fixtures {
		fixtures[i] = makeLatencyFixture(t, i)
		for key, value := range fixtures[i].State {
			state[key] = value
		}
		for key, value := range fixtures[i].Nullifiers {
			nullifiers[key] = value
		}
	}
	indexer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var query struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
			Params struct {
				Leaves []string `json:"leaves"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		source := state
		if query.Method == "getNonInclusionProofs" {
			source = nullifiers
		}
		proofs := make([]any, len(query.Params.Leaves))
		for i, leaf := range query.Params.Leaves {
			proofs[i] = source[leaf]
			if proofs[i] == nil {
				http.Error(w, "unknown leaf", 400)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": query.ID, "result": map[string]any{"context": map[string]any{"slot": 100}, "proofs": proofs}})
	}))
	defer indexer.Close()
	remoteIndexer := delayedEndpoint(indexer.URL, time.Duration(rtt)*time.Millisecond)
	defer remoteIndexer.Close()
	clientResolver, err := indexed.NewResolver(indexed.Config{URL: remoteIndexer.URL, Concurrency: 64})
	if err != nil {
		t.Fatal(err)
	}
	serverResolver, err := indexed.NewResolver(indexed.Config{URL: indexer.URL, Concurrency: 64})
	if err != nil {
		t.Fatal(err)
	}
	keyManager := common.NewLazyKeyManager(options.keys, common.DefaultDownloadConfig())
	ps, err := keyManager.GetTransferSystem(common.TransferConfidentialCircuitType, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	publicWitnesses := make([]backendwitness.Witness, len(fixtures))
	for index, fixture := range fixtures {
		assignment, err := fixture.Params.CreateWitness()
		if err != nil {
			t.Fatal(err)
		}
		if err := gtest.IsSolved(assignment, assignment, ecc.BN254.ScalarField()); err != nil {
			t.Fatal(err)
		}
		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		publicWitnesses[index], err = witness.Public()
		if err != nil {
			t.Fatal(err)
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 64
	client := &http.Client{Transport: transport, Timeout: 60 * time.Second}
	defer transport.CloseIdleConnections()
	for _, workers := range options.workers {
		t.Setenv("PROVER_TRANSFER_CONCURRENCY", fmt.Sprint(workers))
		t.Setenv("PROVER_API_KEY", "")
		address := unusedAddress(t)
		job := server.Run(&server.Config{ProverAddress: address, MetricsAddress: unusedAddress(t), Indexer: serverResolver, TransferExecution: server.NewTransferExecution()}, keyManager)
		stop := sync.OnceFunc(func() { job.RequestStop(); job.AwaitStop() })
		t.Cleanup(stop)
		target := "http://" + address
		for attempt := 0; attempt < 100; attempt++ {
			response, err := client.Get(target + "/health")
			if err == nil {
				response.Body.Close()
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		remote := delayedEndpoint(target, time.Duration(rtt)*time.Millisecond)
		t.Cleanup(remote.Close)
		var calibration []float64
		for count := 0; count < 10; count++ {
			start := time.Now()
			response, err := client.Get(remote.URL + "/health")
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			calibration = append(calibration, float64(time.Since(start).Microseconds())/1000)
		}
		t.Logf("RTT_CALIBRATION workers=%d samples_ms=%v", workers, calibration)
		for _, mode := range options.modes {
			for _, clients := range options.clients {
				if mode == "direct" && rtt != options.rtts[0] {
					continue
				}
				run := func(index int) latencySample {
					fixture := fixtures[index%len(fixtures)]
					request, err := json.Marshal(fixture.Request)
					if err != nil {
						t.Error(err)
						return latencySample{}
					}
					payload, err := json.Marshal(&fixture.Params)
					if err != nil {
						t.Error(err)
						return latencySample{}
					}
					start := time.Now()
					fetchMS := 0.0
					endpoint := remote.URL + "/prove"
					if mode == "client_fetch" {
						resolved, err := clientResolver.Resolve(context.Background(), request)
						if err != nil {
							t.Error(err)
							return latencySample{Status: 0}
						}
						payload = resolved.Payload
						fetchMS = float64(time.Since(start).Microseconds()) / 1000
					}
					if mode == "prover_fetch" {
						endpoint = remote.URL + "/prove/indexed"
						payload = request
					}
					if mode == "direct" {
						endpoint = target + "/prove"
					}
					proofStart := time.Now()
					req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
					if err != nil {
						t.Error(err)
						return latencySample{Status: 0}
					}
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("X-Sync", "true")
					response, err := client.Do(req)
					if err != nil {
						t.Error(err)
						return latencySample{Status: 0}
					}
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					receipt := time.Now()
					sample := latencySample{TotalMS: float64(receipt.Sub(start).Microseconds()) / 1000, FetchMS: fetchMS, ProofHTTPMS: float64(receipt.Sub(proofStart).Microseconds()) / 1000, Status: response.StatusCode}
					if err != nil {
						t.Error(err)
						return sample
					}
					if response.StatusCode != 200 {
						if response.StatusCode == http.StatusTooManyRequests {
							t.Logf("HTTP %d %s", response.StatusCode, body)
						} else {
							t.Errorf("unexpected HTTP %d %s", response.StatusCode, body)
						}
						return sample
					}
					var proof common.Proof
					if err := json.Unmarshal(body, &proof); err != nil {
						t.Errorf("proof decode %s %v", body, err)
						return sample
					}
					sample.Proof = &proof
					return sample
				}
				verify := func(index int, sample *latencySample) {
					if sample.Proof == nil {
						return
					}
					if err := groth16.Verify(sample.Proof.Proof, ps.VerifyingKey, publicWitnesses[index%len(fixtures)]); err != nil {
						t.Error(err)
						return
					}
					sample.Verified = true
				}
				for round := 0; round < 3; round++ {
					warm := make([]latencySample, clients)
					var warming sync.WaitGroup
					for index := range warm {
						warming.Add(1)
						go func(index int) { defer warming.Done(); warm[index] = run(index) }(index)
					}
					warming.Wait()
					good := 0
					for index := range warm {
						verify(index, &warm[index])
						if warm[index].Verified {
							good++
						}
					}
					if good == 0 {
						t.Fatal("warm proofs failed")
					}
				}
				samples := make([]latencySample, options.requests)
				profilePath := ""
				var profile *os.File
				if options.profileDir != "" {
					profilePath = filepath.Join(options.profileDir, fmt.Sprintf("r%d_rtt%d_w%d_c%d_%s.pprof", repeat, rtt, workers, clients, mode))
					profile, err = os.Create(profilePath)
					if err != nil {
						t.Fatal(err)
					}
					if err := pprof.StartCPUProfile(profile); err != nil {
						profile.Close()
						t.Fatal(err)
					}
				}
				usageBefore := benchUsage(t)
				var next atomic.Int64
				var group sync.WaitGroup
				start := time.Now()
				for i := 0; i < clients; i++ {
					group.Add(1)
					go func() {
						defer group.Done()
						for {
							index := int(next.Add(1) - 1)
							if index >= len(samples) {
								return
							}
							samples[index] = run(index)
						}
					}()
				}
				group.Wait()
				elapsed := time.Since(start).Seconds()
				usageAfter := benchUsage(t)
				if profile != nil {
					pprof.StopCPUProfile()
					if err := profile.Close(); err != nil {
						t.Fatal(err)
					}
				}
				for index := range samples {
					verify(index, &samples[index])
				}
				actualRTT := rtt
				calibrated := calibration
				if mode == "direct" {
					actualRTT = 0
					calibrated = nil
				}
				result := latencyResult{Mode: mode, Workers: workers, Clients: clients, Samples: samples, Seconds: elapsed,
					RTTMS: actualRTT, Repeat: repeat, Calibration: calibrated, Profile: profilePath,
					CPUSeconds: usageAfter.cpuSeconds - usageBefore.cpuSeconds, PeakRSS: usageAfter.peakRSS,
					Environment: benchEnvironment{BuildSettings: benchBuildSettings(), GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU(), MaxProcs: runtime.GOMAXPROCS(0), GOGC: os.Getenv("GOGC"), MemoryLimit: os.Getenv("GOMEMLIMIT")}}
				var durations []float64
				for _, sample := range samples {
					if !sample.Verified {
						result.Failures++
					} else {
						durations = append(durations, sample.TotalMS)
					}
				}
				sort.Float64s(durations)
				if len(durations) > 0 {
					result.P50 = durations[len(durations)/2]
					result.P95 = durations[int(math.Ceil(float64(len(durations))*0.95))-1]
				}
				result.TPS = float64(len(durations)) / result.Seconds
				*results = append(*results, result)
				t.Logf("RESULT mode=%s workers=%d clients=%d p50=%.1fms p95=%.1fms tps=%.2f failures=%d", mode, workers, clients, result.P50, result.P95, result.TPS, result.Failures)
				if err := os.MkdirAll(filepath.Dir(options.output), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(options.output, benchEncode(t, *results), 0644); err != nil {
					t.Fatal(err)
				}
			}
		}
		remote.Close()
		stop()
	}
}
