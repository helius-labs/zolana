#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Shape {
    pub n_inputs: usize,
    pub n_outputs: usize,
}

impl Shape {
    pub const fn new(n_inputs: usize, n_outputs: usize) -> Self {
        Self {
            n_inputs,
            n_outputs,
        }
    }
}

/// Shapes the SPP prover has keys for. Slot-signed transactions declare their
/// exact shape (they do not pad), so they validate against this full set rather
/// than [`SUPPORTED_SHAPES`](super::transfer::SUPPORTED_SHAPES). Kept in sync with
/// `sdk-libs/client/src/prover/shape.rs`.
pub const SPP_SUPPORTED_SHAPES: [Shape; 10] = [
    Shape::new(1, 1),
    Shape::new(1, 2),
    Shape::new(2, 2),
    Shape::new(2, 3),
    Shape::new(3, 3),
    Shape::new(4, 3),
    Shape::new(4, 4),
    Shape::new(5, 3),
    Shape::new(5, 4),
    Shape::new(1, 8),
];
