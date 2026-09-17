# Further performance work

The warm merge benchmark on Apple M4 Max with Go arm64 measured 2.10,
2.55, and 2.91 proofs per second at one, two, and four concurrent workers.
Each sample completed four proofs after setup and a verified warm proof.
These short local samples guide experiments and are not a deployment SLO.
Run `go test ./circuits/spp_merge -run '^$' -bench BenchmarkWarmMerge -benchtime=20x`
on the target host and measure client latency under sustained load too.

1. Make Redis dequeue and processing registration atomic, with a renewable
   lease and recovery after worker termination. The current interval between
   removal from the waiting list and processing registration can lose work.
   Verify recovery by terminating a worker during indexer preparation and
   permit waiting.
2. Move process memory sampling out of each proof. Current heap deltas include
   concurrent proofs and garbage collection, so they cannot attribute memory
   to a proof. Sample process memory periodically and measure allocations in
   isolated benchmarks. Compare p95 latency before removing the old metrics.
3. Benchmark CPU affinity and Gnark MSM parallelism together with worker count.
   `GOMAXPROCS` does not independently bound each proof's MSM work. Compare
   representative shapes, P256, merges, memory, and p95 latency on the target
   CPU before selecting scheduler or CPU-specific build settings.
4. Benchmark GPU batching behind the same bounded execution interface. Track
   completed proofs per second and batch waiting separately from single-proof
   latency. Select a maximum batch delay from the client latency target and
   keep CPU capacity for low traffic and unsupported circuits.
5. Profile a representative traffic mix and test a PGO build against the same
   workload. Keep the profile tied to a circuit mix and Go version. Compare
   throughput and p95 latency, not binary size.
6. Consider server push for queued results only after measuring fallback rate.
   Synchronous HTTP already returns the proof without polling. WebSocket push
   saves the result polling delay for queued jobs but still needs admission,
   cancellation, authentication, and reconnect handling.
