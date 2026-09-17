package common

type ResolvedTree struct {
	Tree               string `json:"tree"`
	ID                 uint16 `json:"id"`
	UtxoRoot           string `json:"utxoRoot"`
	NullifierRoot      string `json:"nullifierRoot"`
	UtxoRootIndex      uint16 `json:"utxoRootIndex"`
	NullifierRootIndex uint16 `json:"nullifierRootIndex"`
}

type ProofResolution struct {
	Trees           []ResolvedTree `json:"trees"`
	PublicInputHash string         `json:"publicInputHash"`
}
