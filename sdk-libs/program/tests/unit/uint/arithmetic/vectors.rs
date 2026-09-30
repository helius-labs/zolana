use ark_bn254::Fr;
use ark_ff::One;

use super::fixtures::{result, CheckedAdd, CheckedMul, CheckedSub, Op};
use crate::{
    harness::fixture::{Fixture, Visit},
    uint::rows::{field, max, native, power_of_two, Refused},
};

/// A checked operation at a width above 4, next to where it stops fitting.
#[derive(Clone, Copy, Debug)]
pub struct Edge {
    pub name: &'static str,
    pub op: Op,
    pub bits: u32,
    pub x: Fr,
    pub y: Fr,
    pub fits: bool,
}

impl Edge {
    pub fn visit<V: Visit>(&self, visitor: &V) -> V::Output {
        let (x, y) = (field(self.x), field(self.y));
        let claimed = field(result(self.op, self.x, self.y));
        match (self.op, self.bits) {
            (Op::CheckedAdd, 64) => visitor.visit(&CheckedAdd::<64> { x, y, claimed }),
            (Op::CheckedAdd, 252) => visitor.visit(&CheckedAdd::<252> { x, y, claimed }),
            (Op::CheckedMul, 64) => visitor.visit(&CheckedMul::<64> { x, y, claimed }),
            (Op::CheckedMul, 126) => visitor.visit(&CheckedMul::<126> { x, y, claimed }),
            (Op::CheckedSub, 64) => visitor.visit(&CheckedSub::<64> { x, y, claimed }),
            (Op::CheckedSub, 252) => visitor.visit(&CheckedSub::<252> { x, y, claimed }),
            (op, bits) => panic!("no {op:?} edge fixture at {bits} bits"),
        }
    }

    pub fn native(&self) -> Result<(), Refused> {
        self.visit(&NativeRun)
    }
}

struct NativeRun;

impl Visit for NativeRun {
    type Output = Result<(), Refused>;

    fn visit<F: Fixture>(&self, fixture: &F) -> Self::Output {
        native(fixture)
    }
}

pub fn edges() -> Vec<Edge> {
    let one = Fr::one();
    let zero = Fr::from(0u64);
    let edge = |name, op, bits, x, y, fits| Edge {
        name,
        op,
        bits,
        x,
        y,
        fits,
    };
    vec![
        edge(
            "(2^64 - 2) + 1 fits",
            Op::CheckedAdd,
            64,
            max(64) - one,
            one,
            true,
        ),
        edge(
            "(2^64 - 1) + 1 overflows",
            Op::CheckedAdd,
            64,
            max(64),
            one,
            false,
        ),
        edge(
            "(2^252 - 1) + 0 fits",
            Op::CheckedAdd,
            252,
            max(252),
            zero,
            true,
        ),
        edge(
            "2^251 + 2^251 overflows",
            Op::CheckedAdd,
            252,
            power_of_two(251),
            power_of_two(251),
            false,
        ),
        edge(
            "(2^32 - 1) * (2^32 + 1) fits",
            Op::CheckedMul,
            64,
            max(32),
            power_of_two(32) + one,
            true,
        ),
        edge(
            "2^32 * 2^32 overflows",
            Op::CheckedMul,
            64,
            power_of_two(32),
            power_of_two(32),
            false,
        ),
        edge(
            "(2^126 - 1) * 1 fits",
            Op::CheckedMul,
            126,
            max(126),
            one,
            true,
        ),
        edge(
            "2^63 * 2^63 overflows",
            Op::CheckedMul,
            126,
            power_of_two(63),
            power_of_two(63),
            false,
        ),
        edge(
            "(2^64 - 1) - (2^64 - 1) fits",
            Op::CheckedSub,
            64,
            max(64),
            max(64),
            true,
        ),
        edge("0 - 1 underflows", Op::CheckedSub, 64, zero, one, false),
        edge(
            "(2^252 - 1) - 0 fits",
            Op::CheckedSub,
            252,
            max(252),
            zero,
            true,
        ),
        edge(
            "0 - (2^252 - 1) underflows",
            Op::CheckedSub,
            252,
            zero,
            max(252),
            false,
        ),
    ]
}
