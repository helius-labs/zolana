package keyencryption

import (
	"fmt"
	"testing"
)

func TestR1CSKeyEncryptionShapes(t *testing.T) {
	for _, numKeys := range []uint32{1, 2, 3} {
		numKeys := numKeys
		t.Run(fmt.Sprintf("%d", numKeys), func(t *testing.T) {
			if _, err := R1CSKeyEncryption(numKeys); err != nil {
				t.Fatalf("compile squads key encryption (%d keys): %v", numKeys, err)
			}
		})
	}
}
