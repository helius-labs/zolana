//! Latency of resolving one shielded transaction a caller already has the
//! signature for, against reaching the same transaction through the view tag
//! index, as the tag's history grows.
//!
//! `get_shielded_transactions_by_signature` is one equality on the unique
//! `(signature, event_index)` index. `get_shielded_transactions_by_tags`
//! filters with `EXISTS` subqueries over `rings_outputs`, orders by `slot ASC`,
//! and pages, so a caller looking for the newest transaction walks the whole
//! tag history and re-runs that filter on every page.
//!
//! Read the ratio between the two arms, not the absolute numbers: each sample
//! includes `block_on`, a fresh `extract_context` query, and a transaction
//! begin/commit, which put a floor under both arms and understate the gap.
//!
//! Run with `cargo bench -p photon-indexer --bench rings_signature_lookup`.
//! `signature_lookup_cost_is_independent_of_view_tag_history` is what gates the
//! property in CI; this only measures it, and shares that test's fixture so the
//! two cannot drift apart.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use tokio::runtime::Runtime;

#[path = "../tests/rings_fixtures/mod.rs"]
mod rings_fixtures;

use rings_fixtures::{
    fresh_rings_database, resolve_by_signature, resolve_by_tags, seed_tagged_transaction_history,
    signature_at, LookupCost, PAGE_LIMIT, VIEW_TAG,
};

const HISTORY_LENGTHS: [u64; 4] = [50, 200, 800, 3_200];

fn bench_lookups(criterion: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let mut group = criterion.benchmark_group("resolve_newest_tagged_transaction");

    for history in HISTORY_LENGTHS {
        let db = runtime.block_on(async {
            let db = fresh_rings_database().await;
            seed_tagged_transaction_history(&db, VIEW_TAG, 0..history).await;
            db
        });
        // The newest transaction is last under the tag query's `slot ASC`
        // order, so the tag walk pays for the entire history to reach it.
        let target = signature_at(history - 1);

        // Confirm outside the timed section that both arms really do the work
        // the integration test pins, so a fixture change cannot quietly turn
        // this into a measurement of something else.
        runtime.block_on(async {
            assert_eq!(
                resolve_by_signature(&db, target).await,
                LookupCost {
                    requests: 1,
                    hydrated_transactions: 1,
                }
            );
            assert_eq!(
                resolve_by_tags(&db, VIEW_TAG, target, PAGE_LIMIT).await,
                LookupCost {
                    requests: usize::try_from(history.div_ceil(PAGE_LIMIT))
                        .expect("page count fits in usize"),
                    hydrated_transactions: usize::try_from(history).expect("history fits in usize"),
                }
            );
        });

        group.bench_with_input(
            BenchmarkId::new("by_signature", history),
            &history,
            |bencher, _| {
                bencher.iter(|| black_box(runtime.block_on(resolve_by_signature(&db, target))));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("by_tags", history),
            &history,
            |bencher, _| {
                bencher.iter(|| {
                    black_box(runtime.block_on(resolve_by_tags(&db, VIEW_TAG, target, PAGE_LIMIT)))
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_lookups);
criterion_main!(benches);
