//! Isolated CPU check; endpoint A/B remains the acceptance gate.
use serde::{Serialize, Serializer};
use std::{hint::black_box, time::Instant};
use zolana_indexer_api::Hash;
struct Legacy([u8; 32]);
impl Serialize for Legacy {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&bs58::encode(self.0).into_string())
    }
}
fn timed<T: Serialize>(value: &T) -> f64 {
    let started = Instant::now();
    for _ in 0..100 {
        black_box(serde_json::to_vec(black_box(value)).unwrap());
    }
    started.elapsed().as_secs_f64() * 1000.0
}
fn main() {
    let mut state = 0x1234_5678u32;
    let values = (0..1024)
        .map(|_| {
            let mut bytes = [0u8; 32];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            bytes
        })
        .collect::<Vec<_>>();
    let old = values.iter().copied().map(Legacy).collect::<Vec<_>>();
    let new = values.iter().copied().map(Hash::from).collect::<Vec<_>>();
    assert_eq!(
        serde_json::to_vec(&old).unwrap(),
        serde_json::to_vec(&new).unwrap()
    );
    let mut baseline = Vec::new();
    let mut candidate = Vec::new();
    for sample in 0..10 {
        if sample % 2 == 0 {
            baseline.push(timed(&old));
            candidate.push(timed(&new));
        } else {
            candidate.push(timed(&new));
            baseline.push(timed(&old));
        }
    }
    baseline.sort_by(f64::total_cmp);
    candidate.sort_by(f64::total_cmp);
    println!(
        "{}",
        serde_json::json!({"hashesPerSample":102400,"repeats":10,"baselineMedianMs":baseline[5],"candidateMedianMs":candidate[5],"ratio":candidate[5]/baseline[5]})
    );
}
