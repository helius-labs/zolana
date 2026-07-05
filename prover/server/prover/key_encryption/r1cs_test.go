package keyencryption

import (
	"fmt"
	"testing"
)

// TestR1CSKeyEncryptionShapes confirms the squads key encryption circuit
// compiles to R1CS for the supported recipient counts.
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
