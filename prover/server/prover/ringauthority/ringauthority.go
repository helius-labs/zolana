// Package ringauthority is the ring authority key rule, import free so prover/common and the host mirror in prover-test/spp/protocol share it.
package ringauthority

// MaxInputs mirrors RING_AUTHORITY_MAX_INPUTS in program-libs/interface/src/shape.rs.
const MaxInputs = 40

// Fits mirrors Shape::is_ring_authority for a supported shape spending nInputs.
func Fits(nInputs int) bool {
	return nInputs <= MaxInputs
}
