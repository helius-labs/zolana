package common

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"
	"zolana/prover/prover/keyimage"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/stretchr/testify/require"
)

type keyImageCircuit struct {
	X      frontend.Variable
	Y      frontend.Variable `gnark:",public"`
	Commit bool              `gnark:"-"`
	Rounds int               `gnark:"-"`
}

func (c *keyImageCircuit) Define(api frontend.API) error {
	x := c.X
	for i := 0; i < c.Rounds; i++ {
		x = api.Mul(x, x)
	}
	api.AssertIsEqual(x, c.Y)
	if c.Commit {
		commitment, err := api.(frontend.Committer).Commit(c.X)
		if err != nil {
			return err
		}
		api.AssertIsDifferent(commitment, 0)
	}
	return nil
}

func imageTestSystem(t testing.TB, commit bool, rounds int) *TransferProofSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &keyImageCircuit{Commit: commit, Rounds: rounds})
	require.NoError(t, err)
	pk, vk, err := groth16.Setup(cs)
	require.NoError(t, err)
	return &TransferProofSystem{ProvingKey: pk, VerifyingKey: vk, ConstraintSystem: cs, NInputs: 1, NOutputs: 1}
}

func verifyImageProof(t testing.TB, ps *TransferProofSystem) {
	t.Helper()
	witness, err := frontend.NewWitness(&keyImageCircuit{X: 1, Y: 1}, ecc.BN254.ScalarField())
	require.NoError(t, err)
	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	require.NoError(t, err)
	public, err := witness.Public()
	require.NoError(t, err)
	require.NoError(t, groth16.Verify(proof, ps.VerifyingKey, public))
}

func TestGnarkKeyImageProof(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "commitment"}[commit], func(t *testing.T) {
			ps := imageTestSystem(t, commit, 16)
			var dump bytes.Buffer
			n, err := ps.WriteTo(&dump)
			require.NoError(t, err)
			require.Equal(t, int64(dump.Len()), n)
			path := filepath.Join(t.TempDir(), "transfer_ring_1_1.key")
			require.NoError(t, os.WriteFile(path, dump.Bytes(), 0600))
			loaded, err := ReadSystemFromFile(path)
			require.NoError(t, err)
			require.Equal(t, sha256.Sum256(dump.Bytes()), loaded.(*TransferProofSystem).ProvingKeySha256)
			verifyImageProof(t, loaded.(*TransferProofSystem))
			ps = new(TransferProofSystem)
			read, err := ps.UnsafeReadFrom(&dump)
			require.NoError(t, err)
			require.Equal(t, n, read)
			require.Zero(t, dump.Len())
			verifyImageProof(t, ps)
		})
	}
}

func BenchmarkProvingKeyLoad(b *testing.B) {
	ps := imageTestSystem(b, true, 32768)
	var compressed, image bytes.Buffer
	_, err := ps.ProvingKey.WriteTo(&compressed)
	require.NoError(b, err)
	_, err = keyimage.Write(&image, ps.ProvingKey)
	require.NoError(b, err)
	for _, tc := range []struct {
		name string
		data []byte
		read func(*bytes.Reader, groth16.ProvingKey) error
	}{
		{"compressed", compressed.Bytes(), func(r *bytes.Reader, pk groth16.ProvingKey) error { _, err := pk.UnsafeReadFrom(r); return err }},
		{"image", image.Bytes(), func(r *bytes.Reader, pk groth16.ProvingKey) error { _, err := keyimage.Read(r, pk); return err }},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(tc.data)))
			for b.Loop() {
				require.NoError(b, tc.read(bytes.NewReader(tc.data), groth16.NewProvingKey(ecc.BN254)))
			}
		})
	}
}

// Set ZOLANA_KEY_IMAGE_BENCH_DIR to the conversion script's output directory.
// Both paths read real files from the OS page cache, hash the entire file, and
// deserialize the PK, VK and constraints. Setup/downloads are outside timing.
func BenchmarkPublishedSystemLoad(b *testing.B) {
	dir := os.Getenv("ZOLANA_KEY_IMAGE_BENCH_DIR")
	if dir == "" {
		b.Skip("set ZOLANA_KEY_IMAGE_BENCH_DIR")
	}
	for _, tc := range []struct {
		name   string
		header int64
	}{
		{"custom_ring_base.key", 0},
		{"batch_address-append_40_10.key", 8},
		{"transfer_ring_1_1.key", 12},
		{"transfer_p256_ring_1_1.key", 12},
	} {
		b.Run(tc.name, func(b *testing.B) {
			for _, image := range []bool{false, true} {
				name := "compressed"
				path := filepath.Join(dir, "compressed-source", tc.name)
				if image {
					name = "image"
					path = filepath.Join(dir, tc.name)
				}
				info, err := os.Stat(path)
				require.NoError(b, err)
				b.Run(name, func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(info.Size())
					for b.Loop() {
						if image {
							_, err := ReadSystemFromFile(path)
							require.NoError(b, err)
						} else {
							_, err := readKeyFile(path, func(r io.Reader) (int64, error) {
								n, err := io.CopyN(io.Discard, r, tc.header)
								if err != nil {
									return n, err
								}
								pk := groth16.NewProvingKey(ecc.BN254)
								m, err := pk.UnsafeReadFrom(r)
								n += m
								if err != nil {
									return n, err
								}
								vk := groth16.NewVerifyingKey(ecc.BN254)
								m, err = vk.UnsafeReadFrom(r)
								n += m
								if err != nil {
									return n, err
								}
								cs := groth16.NewCS(ecc.BN254)
								m, err = cs.ReadFrom(r)
								return n + m, err
							})
							require.NoError(b, err)
						}
					}
				})
			}
		})
	}
}
