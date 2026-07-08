package squadszone

import (
	"fmt"
	"testing"
)

// TestR1CSZoneShapes confirms the squads zone circuit compiles to R1CS for the
// supported shapes: (1,1) withdrawal and (2,2) transfer.
func TestR1CSZoneShapes(t *testing.T) {
	for _, shape := range [][2]uint32{{1, 1}, {2, 2}} {
		shape := shape
		t.Run(fmt.Sprintf("%d_%d", shape[0], shape[1]), func(t *testing.T) {
			if _, err := R1CSZone(shape[0], shape[1]); err != nil {
				t.Fatalf("compile squads zone %v: %v", shape, err)
			}
		})
	}
}
