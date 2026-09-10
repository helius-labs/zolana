pub use zolana_interface::shape::{Shape, SPP_AUTO_SHAPES, SPP_SUPPORTED_SHAPES};

use crate::error::TransactionError;

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

    #[test]
    fn automatic_resolution_never_reaches_the_consolidation_shape() {
        assert!(!SPP_AUTO_SHAPES.contains(&Shape::IN36_OUT2));
        assert!(SPP_SUPPORTED_SHAPES.contains(&Shape::IN36_OUT2));
        assert!(canonical_shape(6, 2).is_err());
        assert!(canonical_shape(1, 9).is_err());
        assert_eq!(canonical_shape(1, 1).unwrap(), Shape::IN1_OUT1);
        assert_eq!(canonical_shape(5, 4).unwrap(), Shape::IN5_OUT4);
        assert_eq!(canonical_shape(1, 8).unwrap(), Shape::IN1_OUT8);
    }

    #[test]
    fn the_consolidation_shape_is_reachable_when_declared() {
        assert_eq!(
            resolve_shape(Some(Shape::IN36_OUT2), 36, 2).unwrap(),
            Shape::IN36_OUT2
        );
        assert_eq!(
            resolve_shape(Some(Shape::IN36_OUT2), 6, 1).unwrap(),
            Shape::IN36_OUT2
        );
        assert_eq!(
            resolve_shape(Some(Shape::IN36_OUT2), 37, 2),
            Err(TransactionError::TooManyInputs { got: 37, max: 36 })
        );
        assert_eq!(
            resolve_shape(Some(Shape::IN36_OUT2), 36, 3),
            Err(TransactionError::TooManyOutputsForShape { got: 3, max: 2 })
        );
        assert_eq!(
            resolve_shape(Some(Shape::new(36, 3)), 1, 1),
            Err(TransactionError::UnsupportedShape { n_in: 36, n_out: 3 })
        );
    }
}
