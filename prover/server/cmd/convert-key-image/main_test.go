package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/stretchr/testify/require"
	"zolana/prover/prover/keyimage"
)

type circuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *circuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

func TestConvertPreservesSetupAndSystemTail(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit{})
	require.NoError(t, err)
	pk, vk, err := groth16.Setup(cs)
	require.NoError(t, err)
	var canonical, tail bytes.Buffer
	_, err = pk.WriteTo(&canonical)
	require.NoError(t, err)
	_, err = vk.WriteTo(&tail)
	require.NoError(t, err)
	_, err = cs.WriteTo(&tail)
	require.NoError(t, err)
	for _, header := range []int64{0, 8, 12} {
		t.Run(fmt.Sprint(header), func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input.key")
			output := filepath.Join(dir, "output.key")
			prefix := bytes.Repeat([]byte{7}, int(header))
			source := append(append(append([]byte{}, prefix...), canonical.Bytes()...), tail.Bytes()...)
			require.NoError(t, os.WriteFile(input, source, 0600))
			require.ErrorContains(t, convert(input, output, fmt.Sprintf("%064x", 0), header), "checksum mismatch")
			_, err := os.Stat(output)
			require.True(t, os.IsNotExist(err))
			require.NoError(t, convert(input, output, fmt.Sprintf("%x", sha256.Sum256(source)), header))
			converted, err := os.ReadFile(output)
			require.NoError(t, err)
			require.Equal(t, prefix, converted[:header])
			r := bytes.NewReader(converted[header:])
			loaded := groth16.NewProvingKey(ecc.BN254)
			n, err := keyimage.Read(r, loaded)
			require.NoError(t, err)
			require.Equal(t, tail.Bytes(), converted[header+n:])
			// The full compressed PK must be byte-identical, including domain,
			// infinity maps and all point arrays, not merely its public VK.
			var restored bytes.Buffer
			_, err = loaded.WriteTo(&restored)
			require.NoError(t, err)
			require.Equal(t, canonical.Bytes(), restored.Bytes())
			witness, err := frontend.NewWitness(&circuit{X: 3, Y: 9}, ecc.BN254.ScalarField())
			require.NoError(t, err)
			proof, err := groth16.Prove(cs, loaded, witness)
			require.NoError(t, err)
			public, err := witness.Public()
			require.NoError(t, err)
			require.NoError(t, groth16.Verify(proof, vk, public))
			converted[len(converted)-1] ^= 1
			require.NoError(t, os.WriteFile(output, converted, 0600))
			require.ErrorContains(t, verify(output, fmt.Sprintf("%x", sha256.Sum256(source)), header), "does not reconstruct")
		})
	}
}
