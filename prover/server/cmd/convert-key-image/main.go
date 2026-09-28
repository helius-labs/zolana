// convert-key-image converts an authenticated, compressed proving-system file
// without rerunning setup. The verification key and constraint bytes are copied
// verbatim. This tool is only for the one-time distributed-format migration.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"zolana/prover/prover/keyimage"
)

func main() {
	input := flag.String("input", "", "compressed proving-system file")
	output := flag.String("output", "", "memory-image proving-system file")
	checksum := flag.String("sha256", "", "pinned SHA256 of the input")
	header := flag.Int64("header-bytes", 0, "system header size: ring=0, batch=8, transfer/merge=12")
	verifyOnly := flag.Bool("verify-only", false, "verify that --output reconstructs the pinned input digest")
	flag.Parse()
	if *verifyOnly {
		if err := verify(*output, *checksum, *header); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := convert(*input, *output, *checksum, *header); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func convert(input, output, checksum string, header int64) error {
	expected, err := hex.DecodeString(checksum)
	if err != nil || len(expected) != sha256.Size {
		return fmt.Errorf("--sha256 must be the pinned input digest")
	}
	if header != 0 && header != 8 && header != 12 {
		return fmt.Errorf("invalid system header size")
	}
	f, err := os.Open(input)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != checksum {
		return fmt.Errorf("input checksum mismatch: %s", input)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(output), ".key-image-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	w := bufio.NewWriterSize(tmp, 1<<20)
	if _, err := io.CopyN(w, r, header); err != nil {
		return err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.UnsafeReadFrom(r); err != nil {
		return err
	}
	if _, err := keyimage.Write(w, pk); err != nil {
		return err
	}
	if _, err := io.Copy(w, r); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := verify(tmp.Name(), checksum, header); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), output)
}

// Re-encoding must recover the complete authenticated source byte for byte.
// This checks every PK point, the domain, infinity maps, commitments and tail.
func verify(path, checksum string, header int64) error {
	if header != 0 && header != 8 && header != 12 {
		return fmt.Errorf("invalid system header size")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	h := sha256.New()
	if _, err := io.CopyN(h, r, header); err != nil {
		return err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := keyimage.Read(r, pk); err != nil {
		return err
	}
	w := bufio.NewWriterSize(h, 1<<20)
	if _, err := pk.WriteTo(w); err != nil {
		return err
	}
	if _, err := io.Copy(w, r); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != checksum {
		return fmt.Errorf("converted image does not reconstruct the pinned source")
	}
	return nil
}
