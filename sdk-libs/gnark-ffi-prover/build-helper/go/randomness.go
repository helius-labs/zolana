package gnarkffiprover

import (
	"crypto/rand"
	"crypto/sha256"
	mathrand "math/rand/v2"
	"sync"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// gnark draws all Groth16 setup randomness (the toxic waste, the Pedersen
// commitment G2 point and sigma) and the proof blinding from crypto/rand.Reader
// and takes no randomness source, so an insecure test setup swaps that global
// reader for the duration of the setup. randomness orders the swap against
// every other draw in the archive: an insecure setup holds it exclusively, so
// it consumes the whole fixed stream in order and no proof or regular setup
// ever draws from that stream.
var randomness sync.RWMutex

// insecureTestKeysDomain seeds the insecure test setup together with the
// circuit name. It is public on purpose: the keys it produces are forgeable.
const insecureTestKeysDomain = "zolana-gnark-ffi-prover insecure test keys v1 "

func systemRandomSetup(cs constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	randomness.RLock()
	defer randomness.RUnlock()
	return groth16.Setup(cs)
}

func systemRandomProve(cs constraint.ConstraintSystem, pk groth16.ProvingKey, fullWitness witness.Witness) (groth16.Proof, error) {
	randomness.RLock()
	defer randomness.RUnlock()
	return groth16.Prove(cs, pk, fullWitness)
}

// insecureTestSetup runs the Groth16 setup on a ChaCha8 stream seeded from the
// circuit name. gnark draws every setup value on the calling goroutine in a
// fixed order, so the same constraint system and gnark version always yield
// the same keys.
func insecureTestSetup(name string, cs constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	randomness.Lock()
	defer randomness.Unlock()
	system := rand.Reader
	defer func() { rand.Reader = system }()
	rand.Reader = mathrand.NewChaCha8(sha256.Sum256([]byte(insecureTestKeysDomain + name)))
	return groth16.Setup(cs)
}
