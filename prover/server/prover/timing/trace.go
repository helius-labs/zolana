package timing

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Span struct {
	Name       string  `json:"name"`
	StartMS    float64 `json:"start_ms"`
	DurationMS float64 `json:"duration_ms"`
	Complete   bool    `json:"complete"`
}

type Trace struct {
	start time.Time
	mu    sync.Mutex
	spans []Span
}

type contextKey struct{}

func New() *Trace {
	return &Trace{start: time.Now()}
}

func (t *Trace) Context(ctx context.Context) context.Context {
	if t == nil {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, t)
}

func FromContext(ctx context.Context) *Trace {
	t, _ := ctx.Value(contextKey{}).(*Trace)
	return t
}

func (t *Trace) Start(name string) func() {
	if t == nil {
		return func() {}
	}
	start := time.Now()
	t.mu.Lock()
	if len(t.spans) == 32 {
		t.mu.Unlock()
		return func() {}
	}
	index := len(t.spans)
	t.spans = append(t.spans, Span{Name: name, StartMS: milliseconds(start.Sub(t.start))})
	t.mu.Unlock()
	return sync.OnceFunc(func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		t.spans[index].DurationMS = milliseconds(time.Since(start))
		t.spans[index].Complete = true
	})
}

func (t *Trace) Snapshot() []Span {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	elapsed := milliseconds(time.Since(t.start))
	spans := append([]Span(nil), t.spans...)
	for index := range spans {
		if !spans[index].Complete {
			spans[index].DurationMS = elapsed - spans[index].StartMS
		}
	}
	return append(spans, Span{Name: "server", DurationMS: elapsed, Complete: true})
}

func Header(spans []Span) string {
	values := make([]string, len(spans))
	for index, span := range spans {
		values[index] = fmt.Sprintf("%s;dur=%.3f", span.Name, span.DurationMS)
	}
	return strings.Join(values, ", ")
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}
