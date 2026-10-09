pub use zolana_interface::shape::{Shape, BATCH_SETTLEMENT_SHAPES, SPP_SUPPORTED_SHAPES};

use crate::error::TransactionError;

/// Notes a wallet spend selects at most. Selection pads with random dummies,
/// so the cheapest shape holding this many notes still fits one transaction
/// with two encrypted outputs, inputs from every allowed tree, an owner
/// signer other than the payer and an SPL withdrawal; the next wider shape
/// does not. A wider balance merges first.
pub const MAX_SPEND_INPUTS: usize = 40;

/// Shapes automatic selection may pick: every supported shape except the
/// [`BATCH_SETTLEMENT_SHAPES`], in proving cost order, so the first one that
/// fits is the cheapest. Batch-settlement shapes are declared explicitly.
pub fn auto_shapes() -> impl Iterator<Item = Shape> {
    SPP_SUPPORTED_SHAPES
        .into_iter()
        .filter(|shape| !shape.is_batch_settlement())
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
            if !shape.is_supported() {
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
