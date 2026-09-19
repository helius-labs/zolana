pub use zolana_interface::shape::{Shape, SPP_SUPPORTED_SHAPES};

use crate::error::TransactionError;

/// The consolidation shape: supported, but only reached by declaring it.
pub const SPP_CONSOLIDATION_SHAPE: Shape = Shape::IN36_OUT2;

/// Shapes automatic selection may pick: every supported shape except the
/// consolidation one, which costs a 36-input proof and is only ever reached by
/// declaring it.
pub fn auto_shapes() -> impl Iterator<Item = Shape> {
    SPP_SUPPORTED_SHAPES
        .into_iter()
        .filter(|shape| *shape != SPP_CONSOLIDATION_SHAPE)
}

pub fn canonical_shape(n_in: usize, n_out: usize) -> Result<Shape, TransactionError> {
    auto_shapes()
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
