package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"io"
	"os"
	"path/filepath"
	defaultring "zolana/prover/circuits/spp_transaction/default"
	"zolana/prover/circuits/spp_transaction/shared"
)

func save(path string, write func(io.Writer) (int64, error)) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	if _, err = write(f); err != nil {
		panic(err)
	}
	if err = f.Close(); err != nil {
		panic(err)
	}
}
func main() {
	dir := "proving-keys/cached"
	if err := os.MkdirAll(dir, 0755); err != nil {
		panic(err)
	}
	for _, s := range [][2]int{{1, 1}, {1, 2}, {1, 8}, {2, 2}, {2, 3}, {3, 3}, {4, 3}, {4, 4}, {5, 3}, {5, 4}, {36, 2}} {
		name := fmt.Sprintf("transfer_confidential_cached_%d_%d", s[0], s[1])
		path := filepath.Join(dir, name)
		c, err := defaultring.NewDefaultRingEddsaOnlyCachedCircuit(shared.Shape{NInputs: s[0], NOutputs: s[1]})
		if err != nil {
			panic(err)
		}
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
		if err != nil {
			panic(err)
		}
		if _, err := os.Stat(path + ".vk"); err == nil {
			h := sha256.New()
			if _, err := ccs.WriteTo(h); err != nil {
				panic(err)
			}
			stored, err := os.ReadFile(path + ".r1cs")
			if err != nil {
				panic(err)
			}
			digest := sha256.Sum256(stored)
			if !bytes.Equal(digest[:], h.Sum(nil)) {
				panic("cached UTXO keys do not match circuit: " + path)
			}
			if _, err := os.Stat(path + ".pk"); err != nil {
				panic(err)
			}
			continue
		} else if !os.IsNotExist(err) {
			panic(err)
		}
		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			panic(err)
		}
		save(path+".r1cs", ccs.WriteTo)
		save(path+".pk", pk.WriteTo)
		save(path+".vk", vk.WriteRawTo)
		fmt.Println("GENERATED", path, ccs.GetNbConstraints())
	}
}
