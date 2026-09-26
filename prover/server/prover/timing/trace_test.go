package timing

import (
	"context"
	"sync"
	"testing"
)

func TestConcurrentSpans(t *testing.T) {
	trace := New()
	if FromContext(trace.Context(context.Background())) != trace {
		t.Fatal("request trace was not propagated")
	}
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			finish := trace.Start("rpc")
			finish()
			finish()
			_ = trace.Snapshot()
		})
	}
	workers.Wait()
	spans := trace.Snapshot()
	if len(spans) != 17 {
		t.Fatalf("got %d spans", len(spans))
	}
	total := spans[len(spans)-1].DurationMS
	for _, span := range spans {
		if span.StartMS < 0 || span.DurationMS < 0 || span.StartMS+span.DurationMS > total {
			t.Fatalf("span outside request lifetime: %+v", span)
		}
	}
	spans[0].Name = "modified"
	if trace.Snapshot()[0].Name != "rpc" {
		t.Fatal("snapshot mutated shared state")
	}
}

func TestTraceBoundAndDisabled(t *testing.T) {
	var disabled *Trace
	disabled.Start("unused")()
	ctx := context.Background()
	if disabled.Context(ctx) != ctx || disabled.Snapshot() != nil {
		t.Fatal("disabled trace changed request state")
	}
	trace := New()
	for range 100 {
		trace.Start("rpc")()
	}
	if len(trace.Snapshot()) != 33 {
		t.Fatal("span count is unbounded")
	}
}

func TestSnapshotIncludesRunningWork(t *testing.T) {
	trace := New()
	finish := trace.Start("prove")
	span := trace.Snapshot()[0]
	if span.Complete || span.DurationMS < 0 {
		t.Fatal("unfinished proving was reported as complete")
	}
	finish()
	if !trace.Snapshot()[0].Complete {
		t.Fatal("completed proving was not recorded")
	}
}
