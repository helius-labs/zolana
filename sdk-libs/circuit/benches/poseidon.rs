use std::{hint::black_box, time::Instant};
use spr_circuit::{Field, poseidon};

fn main() {
    for arity in [1, 2, 4, 7, 12] {
        let inputs: Vec<_> = (1..=arity).map(|i| Field::from(i as u64)).collect();
        for _ in 0..50 {
            black_box(poseidon(black_box(&inputs)).unwrap());
        }
        let mut samples = Vec::new();
        for _ in 0..7 {
            let start = Instant::now();
            for _ in 0..500 {
                black_box(poseidon(black_box(&inputs)).unwrap());
            }
            samples.push(start.elapsed().as_nanos() / 500);
        }
        samples.sort_unstable();
        println!(
            "arity={arity} ns/hash: median={} min={} max={}",
            samples[3], samples[0], samples[6]
        );
    }
}
