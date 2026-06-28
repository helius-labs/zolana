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

pub const SUPPORTED_SHAPES: [Shape; 10] = [
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

pub fn canonical_shape(n_in: usize, n_out: usize) -> Result<Shape, ClientError> {
    SUPPORTED_SHAPES
        .iter()
        .copied()
        .find(|s| n_in <= s.n_inputs && n_out <= s.n_outputs)
        .ok_or(ClientError::UnsupportedShape { n_in, n_out })
}

pub fn resolve_shape(
    declared: Option<Shape>,
    n_in: usize,
    n_out: usize,
) -> Result<Shape, ClientError> {
    match declared {
        Some(shape) => {
            if !SUPPORTED_SHAPES.contains(&shape) {
                return Err(ClientError::UnsupportedShape {
                    n_in: shape.n_inputs,
                    n_out: shape.n_outputs,
                });
            }
            if n_in > shape.n_inputs {
                return Err(ClientError::TooManyInputs {
                    got: n_in,
                    max: shape.n_inputs,
                });
            }
            if n_out > shape.n_outputs {
                return Err(ClientError::TooManyOutputs {
                    got: n_out,
                    max: shape.n_outputs,
                });
            }
            Ok(shape)
        }
        None => canonical_shape(n_in, n_out),
    }
}
