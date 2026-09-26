package common

type ResolvedTree struct {
	Tree               string `json:"tree"`
	ID                 uint16 `json:"id"`
	UtxoRoot           string `json:"utxoRoot"`
	NullifierRoot      string `json:"nullifierRoot"`
	UtxoRootIndex      uint16 `json:"utxoRootIndex"`
	NullifierRootIndex uint16 `json:"nullifierRootIndex"`
}

type ResolvedBatch struct {
	Tree       string `json:"tree"`
	StartIndex uint64 `json:"startIndex"`
	OldRoot    string `json:"oldRoot"`
	NewRoot    string `json:"newRoot"`
}

type ProofResolution struct {
	Batch           *ResolvedBatch `json:"batch,omitempty"`
	Trees           []ResolvedTree `json:"trees"`
	PublicInputHash string         `json:"publicInputHash"`
}
