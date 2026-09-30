package server

import (
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
)

type processMemoryCollector struct{}

var systemMemory = prometheus.NewDesc("prover_system_memory_bytes", "Process memory sampled during collection", []string{"type"}, nil)

func init() {
	prometheus.MustRegister(processMemoryCollector{})
}

func (processMemoryCollector) Describe(descriptions chan<- *prometheus.Desc) {
	descriptions <- systemMemory
}

func (processMemoryCollector) Collect(metrics chan<- prometheus.Metric) {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	for _, sample := range []struct {
		name  string
		value uint64
	}{
		{"heap_alloc", memory.HeapAlloc},
		{"heap_sys", memory.HeapSys},
		{"heap_inuse", memory.HeapInuse},
		{"sys", memory.Sys},
	} {
		metrics <- prometheus.MustNewConstMetric(systemMemory, prometheus.GaugeValue, float64(sample.value), sample.name)
	}
}
