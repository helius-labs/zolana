pub use zolana_interface::shape::{Shape, SPP_AUTO_SHAPES, SPP_SUPPORTED_SHAPES};

use crate::error::TransactionError;

/// Smallest shape that fits, when the caller declares none.
///
/// Searches [`SPP_AUTO_SHAPES`], not the full validation set: the large
/// consolidation shape is reachable only by declaring it, so a small transfer is
/// never silently routed to a circuit twenty times its size.
pub fn canonical_shape(n_in: usize, n_out: usize) -> Result<Shape, TransactionError> {
    SPP_AUTO_SHAPES
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The large consolidation shape must never be picked automatically: a
    /// smallest-fit search that included it would route a six-input transfer to
    /// a 36-input circuit, roughly twenty times the constraints for nothing.
    #[test]
    fn automatic_resolution_never_reaches_the_consolidation_shape() {
        assert!(!SPP_AUTO_SHAPES.contains(&Shape::IN36_OUT2));
        assert!(SPP_SUPPORTED_SHAPES.contains(&Shape::IN36_OUT2));

        // Six inputs fit no automatic shape, so this is an error rather than a
        // silent upgrade to the consolidation circuit.
        assert!(canonical_shape(6, 2).is_err());
        assert!(canonical_shape(1, 9).is_err());

        // Inside the automatic set, resolution is unchanged.
        assert_eq!(canonical_shape(1, 1).unwrap(), Shape::IN1_OUT1);
        assert_eq!(canonical_shape(5, 4).unwrap(), Shape::IN5_OUT4);
        assert_eq!(canonical_shape(1, 8).unwrap(), Shape::IN1_OUT8);
    }

    /// Declaring it explicitly is the supported way in, and validation accepts
    /// it because it is in the full set.
    #[test]
    fn the_consolidation_shape_is_reachable_when_declared() {
        assert_eq!(
            resolve_shape(Some(Shape::IN36_OUT2), 36, 2).unwrap(),
            Shape::IN36_OUT2
        );
        assert!(resolve_shape(Some(Shape::IN36_OUT2), 37, 2).is_err());
    }
}
