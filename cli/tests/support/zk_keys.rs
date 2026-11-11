//! Real Xark Groth16 keys for the CLI tests, without any CLI fixture.

use ark_bn254::Fr;
use ark_serialize::{CanonicalSerialize, Compress};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use xark_groth16::{
    r1cs::{ConstraintSource, RowChunk, VarLayout, Window},
    DomainKind,
};

struct EqualityCircuit(VarLayout);

impl ConstraintSource for EqualityCircuit {
    fn layout(&self) -> &VarLayout {
        &self.0
    }
    fn num_constraints(&self) -> usize {
        1
    }
    fn windows(&self, _: usize) -> Vec<Window> {
        vec![Window {
            rows: 0..1,
            handle: 0..1,
        }]
    }
    fn expand(&self, window: &Window, out: &mut RowChunk) {
        out.clear(window.rows.start);
        // public * 1 = private
        for column in [1, 0, 2] {
            out.push_lc([(column, Fr::from(1u64))]);
        }
    }
}

/// Real current-format test keys for a one-row equality constraint, from a
/// setup seeded with `seed`.
pub fn key_bytes(seed: u64) -> (Vec<u8>, Vec<u8>) {
    let source = EqualityCircuit(VarLayout::new([(0, true), (1, false)]));
    let mut pk = Vec::new();
    let vk = xark_groth16::setup::dev_setup(
        &source,
        &mut ChaCha20Rng::seed_from_u64(seed),
        &mut pk,
        Compress::Yes,
        DomainKind::Radix2,
    )
    .unwrap();
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes).unwrap();
    (pk, bytes)
}
