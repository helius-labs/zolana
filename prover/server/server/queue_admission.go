package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/helius-labs/zolana/prover/server/logging"
)

const (
	// Jobs one queue holds before async submissions are refused, unless
	// PROVER_MAX_PENDING_JOBS says otherwise. Each job holds at most one body,
	// so this bounds the bytes a queue can hold too.
	defaultMaxPendingJobs = 4096
	// Seconds a refused submitter is asked to wait.
	queueFullRetryAfterSecs = 5
	// Index entries read per HSCAN round while pruning.
	indexScanCount = 1000
)

// maxPendingJobs is the per-queue bound. 0 disables it.
func maxPendingJobs() int64 {
	if val := os.Getenv("PROVER_MAX_PENDING_JOBS"); val != "" {
		if limit, err := strconv.ParseInt(val, 10, 64); err == nil && limit >= 0 {
			return limit
		}
		logging.Logger().Warn().
			Str("value", val).
			Msg("Ignoring unparseable PROVER_MAX_PENDING_JOBS")
	}
	return defaultMaxPendingJobs
}

// admitPending refuses a submission to a queue already holding limit jobs.
// The count and the push are not atomic, so concurrent submissions can pass
// the bound by at most their number. A Redis error admits: the submission
// meets the same Redis next and fails there with its own error.
func (rq *RedisQueue) admitPending(queueName string, limit int64) *Error {
	if limit <= 0 {
		return nil
	}
	depth, err := rq.pendingDepth(queueName)
	if err != nil {
		logging.Logger().Warn().Err(err).Str("queue", queueName).Msg("Failed to read queue depth, admitting")
		return nil
	}
	if depth < limit {
		return nil
	}
	QueueSubmissionsShedTotal.WithLabelValues(queueName).Inc()
	return &Error{
		StatusCode: http.StatusServiceUnavailable,
		Code:       "queue_full",
		Message:    fmt.Sprintf("%s holds %d pending jobs; retry shortly", queueName, depth),
		RetryAfter: queueFullRetryAfterSecs,
	}
}

// pendingDepth counts the jobs waiting in queueName: its main list, its
// indexed list and, for a fair queue, every tree sub-queue.
func (rq *RedisQueue) pendingDepth(queueName string) (int64, error) {
	var depth int64
	for _, key := range []string{queueName, indexedQueue(queueName)} {
		length, err := rq.Client.LLen(rq.Ctx, key).Result()
		if err != nil {
			return 0, err
		}
		depth += length
	}
	if !isFairQueueEnabled(queueName) {
		return depth, nil
	}
	trees, err := rq.Client.SMembers(rq.Ctx, queueName+":trees").Result()
	if err != nil {
		return 0, err
	}
	for _, tree := range trees {
		length, err := rq.Client.LLen(rq.Ctx, queueName+":"+tree).Result()
		if err != nil {
			return 0, err
		}
		depth += length
	}
	return depth, nil
}

// pruneIndex removes every entry of indexKey whose job is no longer held in
// queueName, where a job is stored under its id plus suffix.
//
// Cleanup used to find an index entry from the job being removed, through the
// zk_input_hash_<job> mapping. A failed job deletes that mapping with its
// in-flight marker, so its failure index entry outlived its job forever and
// zk_failed_index grew by one entry per distinct failed body. Reading the
// index against the queue needs no mapping, and also removes entries that
// earlier provers left behind.
//
// An entry written after the queue is read can be pruned while its job is
// live. The cost is one cache miss: that input is proved again.
func (rq *RedisQueue) pruneIndex(indexKey, queueName, suffix string) (int64, error) {
	items, err := rq.Client.LRange(rq.Ctx, queueName, 0, -1).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to read %s: %w", queueName, err)
	}
	live := make(map[string]bool, len(items))
	for _, item := range items {
		var job ProofJob
		if json.Unmarshal([]byte(item), &job) == nil {
			live[job.ID] = true
		}
	}

	var removed int64
	var cursor uint64
	for {
		entries, next, err := rq.Client.HScan(rq.Ctx, indexKey, cursor, "", indexScanCount).Result()
		if err != nil {
			return removed, fmt.Errorf("failed to scan %s: %w", indexKey, err)
		}
		var stale []string
		for i := 0; i+1 < len(entries); i += 2 {
			if !live[entries[i+1]+suffix] {
				stale = append(stale, entries[i])
			}
		}
		if len(stale) > 0 {
			deleted, err := rq.Client.HDel(rq.Ctx, indexKey, stale...).Result()
			if err != nil {
				return removed, fmt.Errorf("failed to prune %s: %w", indexKey, err)
			}
			removed += deleted
		}
		if next == 0 {
			return removed, nil
		}
		cursor = next
	}
}
