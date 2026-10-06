package server

import (
	"errors"
	"testing"

	"zolana/prover/tee"
)

func TestTEERejectsQueueBeforeStarting(t *testing.T) {
	for _, tc := range []struct {
		name   string
		queue  *RedisQueue
		config *QueueConfig
	}{
		{name: "redis", queue: &RedisQueue{}},
		{name: "enabled", config: &QueueConfig{Enabled: true}},
		{name: "redis with queue disabled", queue: &RedisQueue{}, config: &QueueConfig{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job, err := RunEnhanced(&EnhancedConfig{TEE: &tee.Server{}, Queue: tc.config}, tc.queue, nil)
			if !errors.Is(err, tee.ErrQueueUnsupported) || job.stop != nil || job.closed != nil {
				t.Fatalf("queue configuration started a TEE server: %v", err)
			}
		})
	}
	job, err := RunWithQueue(&Config{TEE: &tee.Server{}}, &RedisQueue{}, nil)
	if !errors.Is(err, tee.ErrQueueUnsupported) || job.stop != nil || job.closed != nil {
		t.Fatalf("queue entry point started a TEE server: %v", err)
	}
}
