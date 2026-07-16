pub use zolana_interface::shape::{Shape, SPP_SUPPORTED_SHAPES};

use crate::error::TransactionError;

pub fn canonical_shape(n_in: usize, n_out: usize) -> Result<Shape, TransactionError> {
    SPP_SUPPORTED_SHAPES
        .into_iter()
        .find(|s| n_in <= s.n_inputs() && n_out <= s.n_outputs())
        .ok_or(TransactionError::UnsupportedShape { n_in, n_out })
}

pub fn resolve_shape(
    declared: Option<Shape>,
    n_in: usize,
    n_out: usize,
) -> Result<Shape, TransactionError> {
    match declared {
        Some(shape) => {
            if !SPP_SUPPORTED_SHAPES.contains(&shape) {
                return Err(TransactionError::UnsupportedShape {
                    n_in: shape.n_inputs(),
                    n_out: shape.n_outputs(),
                });
            }
            if n_in > shape.n_inputs() {
                return Err(TransactionError::TooManyInputs {
                    got: n_in,
                    max: shape.n_inputs(),
                });
            }
            if n_out > shape.n_outputs() {
                return Err(TransactionError::TooManyOutputsForShape {
                    got: n_out,
                    max: shape.n_outputs(),
                });
            }
            Ok(shape)
        }
        None => canonical_shape(n_in, n_out),
    }
}
