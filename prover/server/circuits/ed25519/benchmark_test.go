package ed25519

import (
	"crypto/sha512"
	"slices"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// This test-only boundary permits a like-for-like arithmetic comparison with
// the prehashed P-256 benchmark. The public API always computes SHA-512.
type arithmeticBenchmarkCircuit struct {
	PublicKey [32]frontend.Variable `gnark:",public"`
	Signature [64]frontend.Variable
	Digest    [64]frontend.Variable
}

func (c *arithmeticBenchmarkCircuit) Define(api frontend.API) error {
	verifyDigest(api, c.PublicKey, c.Signature, c.Digest)
	return nil
}

func BenchmarkArithmeticProve(b *testing.B) {
	message := make([]byte, 32)
	input := witnessFor(message)
	transcript := make([]byte, 0, 64+len(message))
	for _, v := range input.Signature[:32] {
		transcript = append(transcript, v.(byte))
	}
	for _, v := range input.PublicKey {
		transcript = append(transcript, v.(byte))
	}
	transcript = append(transcript, message...)
	digest := sha512.Sum512(transcript)
	assignment := &arithmeticBenchmarkCircuit{PublicKey: input.PublicKey, Signature: input.Signature}
	for i, v := range digest {
		assignment.Digest[i] = v
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &arithmeticBenchmarkCircuit{})
	if err != nil {
		b.Fatal(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		b.Fatal(err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	public, err := witness.Public()
	if err != nil {
		b.Fatal(err)
	}
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		b.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		b.Fatal(err)
	}
	var samples []float64
	for b.Loop() {
		start := time.Now()
		if _, err := groth16.Prove(cs, pk, witness); err != nil {
			b.Fatal(err)
		}
		samples = append(samples, float64(time.Since(start))/float64(time.Millisecond))
	}
	slices.Sort(samples)
	b.ReportMetric(samples[len(samples)/2], "median-ms")
	b.ReportMetric(float64(cs.GetNbConstraints()), "constraints")
}
