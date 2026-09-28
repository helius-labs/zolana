package keyimage

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/stretchr/testify/require"
)

func TestFormatDependencies(t *testing.T) {
	mod, err := os.ReadFile("../../go.mod")
	require.NoError(t, err)
	for _, dependency := range strings.Split(dependencies, "; ") {
		require.Contains(t, string(mod), "github.com/consensys/"+dependency+"\n", "key image format must track dependency upgrades")
	}
}

func TestRejectFormatBeforeDumpDecode(t *testing.T) {
	for _, data := range [][]byte{nil, format[:12], make([]byte, 32), append([]byte("old-compressed-format"), make([]byte, 100)...)} {
		n, err := Read(bytes.NewReader(data), groth16.NewProvingKey(ecc.BN254))
		require.Error(t, err)
		require.LessOrEqual(t, n, int64(32))
	}
	n, err := Read(bytes.NewReader(format[:]), groth16.NewProvingKey(ecc.BN254))
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, int64(32), n)
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestShortWrite(t *testing.T) {
	n, err := Write(shortWriter{}, groth16.NewProvingKey(ecc.BN254))
	require.ErrorIs(t, err, io.ErrShortWrite)
	require.Equal(t, int64(31), n)
}

func TestRejectOtherCurve(t *testing.T) {
	pk := groth16.NewProvingKey(ecc.BLS12_381)
	var out bytes.Buffer
	n, err := Write(&out, pk)
	require.ErrorContains(t, err, "require BN254")
	require.Zero(t, n)
	require.Empty(t, out.Bytes())
	n, err = Read(bytes.NewReader(format[:]), pk)
	require.ErrorContains(t, err, "require BN254")
	require.Zero(t, n)
}
