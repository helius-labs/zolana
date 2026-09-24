package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"zolana/prover/prover/common"
)

// A circuit without a route has no path to arrive on and no queue to wait in,
// so the server could never prove it.
func TestEveryCircuitHasARoute(t *testing.T) {
	for _, circuit := range allCircuits() {
		route, ok := RouteForCircuit(circuit)
		if !ok {
			t.Fatalf("%s has no route", circuit)
		}
		if got := GetQueueNameForCircuit(circuit); got != route.Queue() {
			t.Fatalf("%s queues on %q, but its route %s owns %q", circuit, got, route, route.Queue())
		}
	}
}

// Queue names are read by dashboards and by the autoscaling policy, and two
// routes sharing a queue would let one pool drain the other's jobs.
func TestEachRouteOwnsItsQueue(t *testing.T) {
	want := map[ProofRoute][2]string{
		SppRoute:        {"zk_transfer_queue", "zk_transfer_processing_queue"},
		MergeRoute:      {"zk_merge_queue", "zk_merge_processing_queue"},
		CustomRingRoute: {"zk_custom_ring_queue", "zk_custom_ring_processing_queue"},
		ForesterRoute:   {"zk_address_append_queue", "zk_address_append_processing_queue"},
	}
	if len(want) != len(AllProofRoutes) {
		t.Fatalf("pinned %d routes, have %d", len(want), len(AllProofRoutes))
	}
	for _, route := range AllProofRoutes {
		queues := [2]string{route.Queue(), route.ProcessingQueue()}
		if queues != want[route] {
			t.Fatalf("%s queues = %v, want %v", route, queues, want[route])
		}
	}
}

func TestParseProofRoutes(t *testing.T) {
	all, err := ParseProofRoutes(nil)
	if err != nil || len(all) != len(AllProofRoutes) {
		t.Fatalf("no routes named should serve all: got %v, %v", all, err)
	}

	routes, err := ParseProofRoutes([]string{"merge", "forester", "merge"})
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0] != MergeRoute || routes[1] != ForesterRoute {
		t.Fatalf("got %v, want [merge forester]", routes)
	}

	// A typo must stop the deployment, not start a pool serving nothing.
	if _, err := ParseProofRoutes([]string{"spp", "transfer"}); err == nil {
		t.Fatal("unknown route accepted")
	}
}

// newRouteTestMux publishes routes behind an admission that sheds every
// request, so a request the route admits answers 429 prover_busy without
// proving anything, and one it rejects answers before reaching admission.
func newRouteTestMux(routes []ProofRoute, redisQueue *RedisQueue) *http.ServeMux {
	mux := http.NewServeMux()
	registerProofRoutes(mux, routes, proveHandler{
		redisQueue: redisQueue,
		admission:  &syncAdmission{permits: make(chan struct{}, 1), maxWait: 0},
	})
	return mux
}

func postCircuit(mux *http.ServeMux, path string, circuit common.CircuitType) (int, string) {
	// treeHeight satisfies the request parser for address-append; the other
	// circuits ignore it.
	body := fmt.Sprintf(`{"circuitType":%q,"treeHeight":40}`, circuit)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	var reply struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &reply)
	return rec.Code, reply.Code
}

// A route that proved any circuit would let a caller buy an expensive proof at
// a cheap route's price, and would load keys onto a pool never sized for them.
func TestRoutePathAdmitsOnlyItsCircuits(t *testing.T) {
	mux := newRouteTestMux(AllProofRoutes, nil)
	for _, circuit := range allCircuits() {
		own, _ := RouteForCircuit(circuit)
		for _, route := range AllProofRoutes {
			for _, path := range []string{route.Path(), gatewayPrefix + route.Path()} {
				status, code := postCircuit(mux, path, circuit)
				if route == own {
					if status != http.StatusTooManyRequests || code != "prover_busy" {
						t.Fatalf("%s on %s: got %d %q, want it admitted", circuit, path, status, code)
					}
					continue
				}
				if status != http.StatusBadRequest || code != "circuit_not_served" {
					t.Fatalf("%s on %s: got %d %q, want circuit_not_served", circuit, path, status, code)
				}
			}
		}
	}
}

// A deployment serving some routes must neither publish the others nor prove
// their circuits through the pre-route path.
func TestUnservedRouteIsNotPublished(t *testing.T) {
	mux := newRouteTestMux([]ProofRoute{ForesterRoute}, nil)

	if status, _ := postCircuit(mux, SppRoute.Path(), common.TransferConfidentialCircuitType); status != http.StatusNotFound {
		t.Fatalf("unserved route answered %d, want 404", status)
	}
	if status, code := postCircuit(mux, "/prove", common.TransferConfidentialCircuitType); code != "circuit_not_served" {
		t.Fatalf("pre-route path proved an unserved circuit: %d %q", status, code)
	}
	if status, code := postCircuit(mux, "/prove", common.BatchAddressAppendCircuitType); code != "prover_busy" {
		t.Fatalf("pre-route path rejected a served circuit: %d %q", status, code)
	}
	if status, code := postCircuit(mux, ForesterRoute.Path(), common.BatchAddressAppendCircuitType); code != "prover_busy" {
		t.Fatalf("served route rejected its circuit: %d %q", status, code)
	}
}

func TestUnknownCircuitIsMalformed(t *testing.T) {
	mux := newRouteTestMux(AllProofRoutes, nil)
	if status, code := postCircuit(mux, SppRoute.Path(), "unknown"); status != http.StatusBadRequest || code != "malformed_body" {
		t.Fatalf("got %d %q, want 400 malformed_body", status, code)
	}
}

// The gateway sends a poll to the pool serving the route, so each route has
// its own status path, published only where a queue can hold a job.
func TestStatusPathsFollowTheQueue(t *testing.T) {
	get := func(mux *http.ServeMux, path string) int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}

	queued := newRouteTestMux([]ProofRoute{MergeRoute}, &RedisQueue{})
	// A poll without a jobId is rejected by the status handler itself, before
	// any Redis read, which proves the path reached it.
	for _, path := range []string{MergeRoute.StatusPath(), gatewayPrefix + MergeRoute.StatusPath(), "/prove/status"} {
		if status := get(queued, path); status != http.StatusBadRequest {
			t.Fatalf("%s: got %d, want the status handler's 400", path, status)
		}
	}
	if status := get(queued, SppRoute.StatusPath()); status != http.StatusNotFound {
		t.Fatalf("unserved route's status path answered %d, want 404", status)
	}

	unqueued := newRouteTestMux([]ProofRoute{MergeRoute}, nil)
	if status := get(unqueued, MergeRoute.StatusPath()); status != http.StatusNotFound {
		t.Fatalf("status path without a queue answered %d, want 404", status)
	}
}
