package common

import (
	"strings"
	"testing"
)

func TestProofRequestMetaDoesNotReturnWitnessData(t *testing.T) {
	const marker = "private-witness-marker"
	_, err := ParseProofRequestMeta([]byte(`{"txViewingSk":"` + marker + `"}`))
	if err == nil {
		t.Fatal("missing circuit type accepted")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatal("error contains witness data")
	}
}
