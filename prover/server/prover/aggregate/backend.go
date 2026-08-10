package aggregate

// Backend names the prover that served an aggregate job.
type Backend string

const (
	// BackendGnarkCPU is gnark's stock prover, the only backend of the
	// default build and the fallback of the cuda build.
	BackendGnarkCPU Backend = "gnark-cpu"
	// BackendWitgenGPU is the device-witness prover from helios witgen.
	BackendWitgenGPU Backend = "witgen-gpu"
)
