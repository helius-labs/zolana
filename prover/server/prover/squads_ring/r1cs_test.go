package squadsring

import (
	"fmt"
	"testing"
)

func TestR1CSRingShapes(t *testing.T) {
	for _, shape := range [][2]uint32{{1, 1}, {2, 2}} {
		t.Run(fmt.Sprintf("%d_%d", shape[0], shape[1]), func(t *testing.T) {
			if _, err := R1CSRing(shape[0], shape[1]); err != nil {
				t.Fatalf("compile squads ring %v: %v", shape, err)
			}
		})
	}
}
