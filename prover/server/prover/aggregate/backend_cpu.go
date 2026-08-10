//go:build !cuda

package aggregate

import "zolana/prover/prover/common"

// ProveAggregateBackend serves a batch on the only backend this build
// carries. The cuda build replaces this with the device-witness route.
func ProveAggregateBackend(ps *common.AggregateProofSystem, legs []Leg) (*common.Proof, Backend, error) {
	proof, err := ProveAggregate(ps, legs)
	return proof, BackendGnarkCPU, err
}
