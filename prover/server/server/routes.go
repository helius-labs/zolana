package server

import (
	"fmt"
	"net/http"
	"strings"
	"zolana/prover/prover/common"
	customring "zolana/prover/prover/custom_ring"
)

// ProofRoute is one proving path, /prove/<route>, grouping circuits by the
// caller and cost profile they share.
//
// The route lives in the path because the Helius gateway routes and meters
// REST calls on (method, path) alone and never reads a body. One path per route
// lets it send each route to its own prover pool and price it separately; the
// circuitType in the body still selects the circuit within the route.
//
// Each route owns one Redis queue, so pools serving different routes can share
// a Redis database without draining each other's jobs.
type ProofRoute string

const (
	SppRoute        ProofRoute = "spp"
	MergeRoute      ProofRoute = "merge"
	CustomRingRoute ProofRoute = "custom-ring"
	ForesterRoute   ProofRoute = "forester"
)

var AllProofRoutes = []ProofRoute{SppRoute, MergeRoute, CustomRingRoute, ForesterRoute}

// RouteForCircuit returns the route that proves circuit, or false for a
// circuit this server does not prove.
func RouteForCircuit(circuit common.CircuitType) (ProofRoute, bool) {
	if circuit.IsRing() {
		return CustomRingRoute, true
	}
	switch circuit {
	case common.TransferConfidentialCircuitType,
		common.TransferRingCircuitType,
		common.TransferP256RingCircuitType,
		common.TransferRingAuthorityCircuitType:
		return SppRoute, true
	case common.MergeCircuitType, common.MergeRingCircuitType:
		return MergeRoute, true
	case common.BatchAddressAppendCircuitType:
		return ForesterRoute, true
	default:
		return "", false
	}
}

func (route ProofRoute) Path() string {
	return "/prove/" + string(route)
}

// StatusPath is per route so the gateway can send a poll to the pool that
// holds the job. It carries no access control: the job id is an unguessable
// UUID, and checking the circuit would cost a Redis read on the hottest path.
func (route ProofRoute) StatusPath() string {
	return route.Path() + "/status"
}

func (route ProofRoute) Queue() string {
	switch route {
	case SppRoute:
		return "zk_transfer_queue"
	case MergeRoute:
		return "zk_merge_queue"
	case CustomRingRoute:
		return "zk_custom_ring_queue"
	case ForesterRoute:
		return "zk_address_append_queue"
	default:
		return ""
	}
}

func (route ProofRoute) ProcessingQueue() string {
	queue := route.Queue()
	if queue == "" {
		return ""
	}
	return strings.TrimSuffix(queue, "_queue") + "_processing_queue"
}

// ParseProofRoutes validates the routes a deployment serves. None named means
// every route, which is what a single shared prover and local development run.
func ParseProofRoutes(names []string) ([]ProofRoute, error) {
	if len(names) == 0 {
		return AllProofRoutes, nil
	}
	var routes []ProofRoute
	for _, name := range names {
		route, err := parseProofRoute(name)
		if err != nil {
			return nil, err
		}
		if !containsRoute(routes, route) {
			routes = append(routes, route)
		}
	}
	return routes, nil
}

func parseProofRoute(name string) (ProofRoute, error) {
	for _, route := range AllProofRoutes {
		if string(route) == name {
			return route, nil
		}
	}
	valid := make([]string, len(AllProofRoutes))
	for i, route := range AllProofRoutes {
		valid[i] = string(route)
	}
	return "", fmt.Errorf("unknown proof route %q (valid: %s)", name, strings.Join(valid, ", "))
}

func containsRoute(routes []ProofRoute, route ProofRoute) bool {
	for _, candidate := range routes {
		if candidate == route {
			return true
		}
	}
	return false
}

func servesCircuit(routes []ProofRoute, circuit common.CircuitType) bool {
	route, ok := RouteForCircuit(circuit)
	return ok && containsRoute(routes, route)
}

// allCircuits is every circuit this binary proves.
func allCircuits() []common.CircuitType {
	circuits := []common.CircuitType{
		common.BatchAddressAppendCircuitType,
		common.TransferConfidentialCircuitType,
		common.TransferRingCircuitType,
		common.TransferP256RingCircuitType,
		common.TransferRingAuthorityCircuitType,
		common.MergeCircuitType,
		common.MergeRingCircuitType,
	}
	for _, ring := range customring.RingCircuits {
		circuits = append(circuits, ring.Type)
	}
	return circuits
}

// servedCircuits is the circuits a deployment serving routes proves.
func servedCircuits(routes []ProofRoute) []common.CircuitType {
	var circuits []common.CircuitType
	for _, circuit := range allCircuits() {
		if servesCircuit(routes, circuit) {
			circuits = append(circuits, circuit)
		}
	}
	return circuits
}

// admitCircuit rejects a circuit the path does not serve. Without it a caller
// could send an expensive circuit down a cheaply metered route, and a pool
// would load keys for circuits it was never sized for.
func admitCircuit(served []ProofRoute, circuit common.CircuitType, path string) *Error {
	route, ok := RouteForCircuit(circuit)
	if !ok {
		return malformedBodyError(fmt.Errorf("unknown circuit type: %s", circuit))
	}
	if containsRoute(served, route) {
		return nil
	}
	return &Error{
		StatusCode: http.StatusBadRequest,
		Code:       "circuit_not_served",
		Message:    fmt.Sprintf("%s is not proved on %s; send it to %s", circuit, path, route.Path()),
	}
}

// routeQueues lists every route's pending queue.
func routeQueues() []string {
	queues := make([]string, len(AllProofRoutes))
	for i, route := range AllProofRoutes {
		queues[i] = route.Queue()
	}
	return queues
}

// routeProcessingQueues lists every route's processing queue.
func routeProcessingQueues() []string {
	queues := make([]string, len(AllProofRoutes))
	for i, route := range AllProofRoutes {
		queues[i] = route.ProcessingQueue()
	}
	return queues
}

func sumQueues(stats map[string]int64, queues []string) int64 {
	var total int64
	for _, queue := range queues {
		total += stats[queue]
	}
	return total
}
