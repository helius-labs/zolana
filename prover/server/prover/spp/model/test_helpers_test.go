package model

func sampleUtxo(base int) Utxo {
	return Utxo{
		Domain:        fe(int64(base + 1)),
		Owner:         fe(int64(base + 2)),
		AssetID:       fe(int64(base + 3)),
		AssetAmount:   fe(int64(base + 4)),
		Blinding:      fe(int64(base + 5)),
		DataHash:      fe(int64(base + 6)),
		ZoneDataHash:  fe(int64(base + 7)),
		ZoneProgramID: fe(int64(base + 8)),
	}
}
