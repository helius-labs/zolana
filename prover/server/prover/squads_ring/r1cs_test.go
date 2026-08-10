package squadszone

import (
	"fmt"
	"testing"
)

func TestR1CSZoneShapes(t *testing.T) {
	for _, shape := range [][2]uint32{{1, 1}, {2, 2}} {
		t.Run(fmt.Sprintf("%d_%d", shape[0], shape[1]), func(t *testing.T) {
			if _, err := R1CSZone(shape[0], shape[1]); err != nil {
				t.Fatalf("compile squads zone %v: %v", shape, err)
			}
		})
	}
}
