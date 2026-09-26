package nullifiertreetest

import (
	"fmt"
	"os"
	"testing"
	merkletree "zolana/prover/merkle-tree"
	"zolana/prover/prover-test/aeglosfixture"
)

func TestExportAeglosForesterFixtures(t *testing.T) {
	if os.Getenv("AEGLOS_FIXTURES") == "" {
		t.Skip("AEGLOS_FIXTURES is unset")
	}
	for _, batch := range []uint32{10, 250} {
		var previous *merkletree.IndexedMerkleTree
		for variant := range 2 {
			params, err := BuildTestAddressTree(40, batch, previous, uint64(variant)*uint64(batch)+1)
			if err != nil {
				t.Fatal(err)
			}
			previous = params.Tree
			assignment, err := params.CreateWitness()
			if err != nil {
				t.Fatal(err)
			}
			aeglosfixture.Write(t, fmt.Sprintf("batch_address-append_40_%d.key", batch), variant, assignment)
		}
	}
}
