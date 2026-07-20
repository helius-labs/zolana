package common

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"zolana/prover/logging"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	gnarkio "github.com/consensys/gnark/io"
)

type RunMode string

const (
	Forester     RunMode = "forester"
	ForesterTest RunMode = "forester-test"
	Rpc          RunMode = "rpc"
	Full         RunMode = "full"
	FullTest     RunMode = "full-test"
	LocalRpc     RunMode = "local-rpc"
)

// Trusted setup utility functions
// Taken from: https://github.com/bnb-chain/zkbnb/blob/master/common/prove/proof_keys.go#L19

func LoadProvingKey(filepath string) (pk groth16.ProvingKey, err error) {
	logging.Logger().Info().
		Str("filepath", filepath).
		Msg("start reading proving key")

	pk = groth16.NewProvingKey(ecc.BN254)
	f, err := os.Open(filepath)
	if err != nil {
		logging.Logger().Error().
			Str("filepath", filepath).
			Err(err).
			Msg("error opening proving key file")
		return pk, fmt.Errorf("error opening proving key file: %v", err)
	}
	defer f.Close()

	fileInfo, err := f.Stat()
	if err != nil {
		logging.Logger().Error().
			Str("filepath", filepath).
			Err(err).
			Msg("error getting proving key file info")
		return pk, fmt.Errorf("error getting file info: %v", err)
	}

	logging.Logger().Info().
		Str("filepath", filepath).
		Int64("size", fileInfo.Size()).
		Msg("proving key file stats")

	n, err := pk.ReadFrom(f)
	if err != nil {
		logging.Logger().Error().
			Str("filepath", filepath).
			Int64("bytesRead", n).
			Err(err).
			Msg("error reading proving key file")
		return pk, fmt.Errorf("error reading proving key: %v", err)
	}

	logging.Logger().Info().
		Str("filepath", filepath).
		Int64("bytesRead", n).
		Msg("successfully read proving key")

	return pk, nil
}

// Taken from: https://github.com/bnb-chain/zkbnb/blob/master/common/prove/proof_keys.go#L32
func LoadVerifyingKey(filepath string) (verifyingKey groth16.VerifyingKey, err error) {
	logging.Logger().Info().Msg("start reading verifying key")
	verifyingKey = groth16.NewVerifyingKey(ecc.BN254)
	f, _ := os.Open(filepath)
	_, err = verifyingKey.ReadFrom(f)
	if err != nil {
		return verifyingKey, fmt.Errorf("read file error")
	}
	err = f.Close()
	if err != nil {
		return nil, err
	}

	return verifyingKey, nil
}

func LoadConstraintSystem(filepath string) (constraint.ConstraintSystem, error) {
	logging.Logger().Info().Str("filepath", filepath).Msg("start reading constraint system")
	cs := groth16.NewCS(ecc.BN254)
	f, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("error opening constraint system file: %v", err)
	}
	defer f.Close()

	_, err = cs.ReadFrom(f)
	if err != nil {
		return nil, fmt.Errorf("error reading constraint system: %v", err)
	}

	return cs, nil
}

// GetKeys returns the proving-key paths to preload for a run-mode / circuit set.
// Only the batched address-append keys (the forester's nullifier tree) are
// preloaded here; transfer and merge keys load lazily per request.
func GetKeys(keysDir string, runMode RunMode, circuits []string) []string {
	var keys []string

	addressAppendKeys := []string{filepath.Join(keysDir, "batch_address-append_40_250.key")}
	addressAppendTestKeys := []string{filepath.Join(keysDir, "batch_address-append_40_10.key")}

	switch runMode {
	case Forester, Full:
		keys = append(keys, addressAppendKeys...)
	case ForesterTest, FullTest:
		keys = append(keys, addressAppendTestKeys...)
	}

	for _, circuit := range circuits {
		switch circuit {
		case "address-append":
			keys = append(keys, addressAppendKeys...)
		case "address-append-test":
			keys = append(keys, addressAppendTestKeys...)
		}
	}
	seen := make(map[string]bool)
	var uniqueKeys []string
	for _, key := range keys {
		if !seen[key] {
			seen[key] = true
			uniqueKeys = append(uniqueKeys, key)
		}
	}

	logging.Logger().Info().
		Strs("keys", uniqueKeys).
		Msg("Loading proving system keys")

	return uniqueKeys
}

func LoadKeys(keysDirPath string, runMode RunMode, circuits []string) ([]*BatchProofSystem, error) {
	return LoadKeysWithConfig(keysDirPath, runMode, circuits, DefaultDownloadConfig())
}

func LoadKeysWithConfig(keysDirPath string, runMode RunMode, circuits []string, config *DownloadConfig) ([]*BatchProofSystem, error) {
	var pssv2 []*BatchProofSystem
	keys := GetKeys(keysDirPath, runMode, circuits)

	// Ensure all required keys exist (download if necessary)
	if err := EnsureKeysExist(keys, config); err != nil {
		return nil, fmt.Errorf("failed to ensure keys exist: %w", err)
	}

	for _, key := range keys {
		logging.Logger().Info().Msg("Reading proving system from file " + key + "...")
		system, err := ReadSystemFromFile(key)
		if err != nil {
			return nil, err
		}
		switch s := system.(type) {
		case *BatchProofSystem:
			pssv2 = append(pssv2, s)
			logging.Logger().Info().
				Uint32("treeHeight", s.TreeHeight).
				Uint32("batchSize", s.BatchSize).
				Msg("Read BatchProofSystem")
		default:
			return nil, fmt.Errorf("unknown proving system type")
		}
	}
	return pssv2, nil
}

func createFileAndWriteBytes(filePath string, data []byte) error {
	fmt.Println("Writing", len(data), "bytes to", filePath)
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			return
		}
	}(file)

	_, err = io.WriteString(file, fmt.Sprintf("%d", data))
	if err != nil {
		return err
	}
	fmt.Println("Wrote", len(data), "bytes to", filePath)
	return nil
}

func WriteProvingSystem(system interface{}, path string, pathVkey string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var written int64
	switch s := system.(type) {
	case *BatchProofSystem:
		written, err = s.WriteTo(file)
	case *TransferProofSystem:
		written, err = s.WriteTo(file)
	default:
		return fmt.Errorf("unknown proving system type")
	}

	if err != nil {
		return err
	}

	logging.Logger().Info().Int64("bytesWritten", written).Msg("Proving system written to file")

	// Only write separate vkey file if path is provided
	if pathVkey != "" {
		var vk interface{}
		switch s := system.(type) {
		case *BatchProofSystem:
			vk = s.VerifyingKey
		case *TransferProofSystem:
			vk = s.VerifyingKey
		}

		var buf bytes.Buffer
		_, err = vk.(gnarkio.WriterRawTo).WriteRawTo(&buf)
		if err != nil {
			return err
		}

		// Write vkey in text format for cargo xtask: [byte1 byte2 byte3 ...]
		proofBytes := buf.Bytes()
		vkeyFile, err := os.Create(pathVkey)
		if err != nil {
			return err
		}
		defer vkeyFile.Close()

		vkeyFile.WriteString("[")
		for i, b := range proofBytes {
			if i > 0 {
				vkeyFile.WriteString(" ")
			}
			fmt.Fprintf(vkeyFile, "%d", b)
		}
		vkeyFile.WriteString("]")
	}

	return nil
}
