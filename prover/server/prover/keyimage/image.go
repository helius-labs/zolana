// Package keyimage stores BN254 Groth16 proving keys as native point arrays.
// Files must be trusted (distributed files are authenticated by proving-keys.lock)
// before Read: gnark's dump decoder does not validate point arrays or lengths.
package keyimage

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
)

// Updating either dependency requires converting the published keys again.
// TestFormatDependencies pins this identifier to go.mod.
const dependencies = "gnark v0.16.3; gnark-crypto v0.21.0"

// BN254 points are arrays of uint64 Montgomery limbs, identical on amd64 and
// arm64. No Go pointers, slice headers, padding or machine-sized ints are dumped.
var format = sha256.Sum256([]byte("zolana-bn254-pk-image-v1; little-endian; " + dependencies))

type reader struct {
	io.Reader
	n int64
}

func (r *reader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.n += int64(n)
	return n, err
}

type writer struct {
	io.Writer
	n int64
}

func (w *writer) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	w.n += int64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

func supported() error {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("proving key images require amd64 or arm64, got %s", runtime.GOARCH)
	}
	return nil
}

// Write writes a versioned BN254 image and reports the bytes written.
func Write(w io.Writer, pk groth16.ProvingKey) (int64, error) {
	if pk.CurveID() != ecc.BN254 {
		return 0, fmt.Errorf("proving key images require BN254")
	}
	if err := supported(); err != nil {
		return 0, err
	}
	out := &writer{Writer: w}
	if _, err := out.Write(format[:]); err != nil {
		return out.n, err
	}
	err := pk.WriteDump(out)
	return out.n, err
}

// Read loads a trusted BN254 image and reports the bytes consumed.
// Callers must verify externally supplied files against their pinned checksum
// before calling Read. Curve checks are deliberately skipped.
func Read(r io.Reader, pk groth16.ProvingKey) (int64, error) {
	if pk.CurveID() != ecc.BN254 {
		return 0, fmt.Errorf("proving key images require BN254")
	}
	if err := supported(); err != nil {
		return 0, err
	}
	in := &reader{Reader: r}
	var header [32]byte
	if _, err := io.ReadFull(in, header[:]); err != nil {
		return in.n, err
	}
	if !bytes.Equal(header[:], format[:]) {
		return in.n, fmt.Errorf("unsupported proving key image format; convert the key with cmd/convert-key-image")
	}
	err := pk.ReadDump(in)
	return in.n, err
}
