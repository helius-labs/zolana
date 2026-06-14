use crate::error::ClientError;

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

pub const SUPPORTED_SHAPES: [Shape; 1] = [Shape::new(2, 3)];

pub fn canonical_shape(n_in: usize, n_out: usize) -> Result<Shape, ClientError> {
    SUPPORTED_SHAPES
        .iter()
        .copied()
        .find(|s| n_in <= s.n_inputs && n_out <= s.n_outputs)
        .ok_or(ClientError::UnsupportedShape { n_in, n_out })
}
