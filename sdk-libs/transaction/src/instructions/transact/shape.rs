pub use zolana_interface::shape::{Shape, SPP_SUPPORTED_SHAPES};

use crate::error::TransactionError;

/// The consolidation shape: the only supported shape above five inputs.
pub const SPP_CONSOLIDATION_SHAPE: Shape = Shape::IN36_OUT2;

/// Shapes wallet coin selection may fill: every supported shape except the
/// consolidation one, which costs a 36-input proof. A wallet holding more
/// UTXOs than these shapes take merges them first.
pub fn auto_shapes() -> impl Iterator<Item = Shape> {
    SPP_SUPPORTED_SHAPES
        .into_iter()
        .filter(|shape| *shape != SPP_CONSOLIDATION_SHAPE)
}

/// The first supported shape that fits. The consolidation shape comes last, so
/// it is selected only for more than five inputs.
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
