package buildcheck

import (
	"runtime/debug"
	"testing"
)

func TestRejectSlowBuilds(t *testing.T) {
	for _, setting := range []debug.BuildSetting{
		{Key: "-gcflags", Value: "all=-N -l"}, {Key: "-gcflags", Value: "zolana/prover/...=-l"},
		{Key: "-race", Value: "true"}, {Key: "-tags", Value: "icicle,purego"},
		{Key: "-tags", Value: "noasm"},
	} {
		if Optimized(&debug.BuildInfo{Settings: []debug.BuildSetting{setting}}) == nil {
			t.Fatalf("accepted slow build %v", setting)
		}
	}
	if Optimized(&debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "-gcflags", Value: "-d=checkptr=0"}}}) != nil {
		t.Fatal("rejected optimized build")
	}
}
