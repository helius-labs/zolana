package protocol

func sampleUtxo(base int) Utxo {
	return Utxo{
		Domain:        fe(int64(base + 1)),
		Owner:         fe(int64(base + 2)),
		Asset:         fe(int64(base + 3)),
		Amount:        fe(int64(base + 4)),
		Blinding:      fe(int64(base + 5)),
		DataHash:      fe(int64(base + 6)),
		RingDataHash:  fe(int64(base + 7)),
		RingProgramID: fe(int64(base + 8)),
	}
}
