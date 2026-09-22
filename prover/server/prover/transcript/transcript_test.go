package transcript_test

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"zolana/prover/prover/common"
	prooftranscript "zolana/prover/prover/transcript"
)

func TestIndexedTranscriptVector(t *testing.T) {
	data, err := os.ReadFile("../../../../sdk-libs/fixtures/indexed-proof.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		PublicInputs []string `json:"publicInputs"`
		Trees        []struct {
			ID            uint16 `json:"id"`
			UtxoRoot      string `json:"utxoRoot"`
			NullifierRoot string `json:"nullifierRoot"`
		} `json:"trees"`
		PublicInputHash string `json:"publicInputHash"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	slots := make([]*big.Int, 5)
	for index := range slots {
		fields := []*big.Int{new(big.Int), new(big.Int), new(big.Int)}
		if index < len(vector.Trees) {
			tree := vector.Trees[index]
			fields[0].SetUint64(uint64(tree.ID))
			fields[1], err = common.FeFromHex(tree.UtxoRoot)
			if err != nil {
				t.Fatal(err)
			}
			fields[2], err = common.FeFromHex(tree.NullifierRoot)
			if err != nil {
				t.Fatal(err)
			}
		}
		slots[index], err = prooftranscript.HashFields(fields)
		if err != nil {
			t.Fatal(err)
		}
	}
	tree, err := prooftranscript.RightHashChain(slots)
	if err != nil {
		t.Fatal(err)
	}
	public, err := common.FeFromHexSlice(vector.PublicInputs)
	if err != nil {
		t.Fatal(err)
	}
	transcript := append([]*big.Int{}, public[:2]...)
	transcript = append(transcript, tree)
	transcript = append(transcript, public[2:]...)
	hash, err := prooftranscript.HashChain4(transcript)
	if err != nil {
		t.Fatal(err)
	}
	if common.FeHex(hash) != vector.PublicInputHash {
		t.Fatal("public transcript differs from the shared vector")
	}
}
