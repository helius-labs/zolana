use solana_address::Address;
pub use zolana_interface::shape::{Shape, CONFIDENTIAL_EDDSA_SHAPES, SPP_SUPPORTED_SHAPES};

use crate::error::TransactionError;

/// The default-ring transact rail a transaction proves on. Each rail has its
/// own key set, so its own shapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactRail {
    /// Every input owner signs the transaction; `CircuitId::ConfidentialSigner`.
    ConfidentialSigner,
    /// One owner authorizes the spend with an Ed25519 signature the proof
    /// verifies, so that owner does not sign the transaction;
    /// `CircuitId::ConfidentialEddsa`.
    ConfidentialEddsa,
}

impl TransactRail {
    /// The rail a transaction with these owner signers proves on when exactly
    /// `transaction_signers` sign it: the signer rail when every owner signs,
    /// the in-circuit rail when one owner does not (a relayer pays, say).
    pub fn select(owner_signers: &[Address], transaction_signers: &[Address]) -> Self {
        if owner_signers
            .iter()
            .all(|owner| transaction_signers.contains(owner))
        {
            Self::ConfidentialSigner
        } else {
            Self::ConfidentialEddsa
        }
    }

    /// The shapes the rail has keys for, in proving cost order.
    pub fn shapes(self) -> &'static [Shape] {
        match self {
            Self::ConfidentialSigner => &SPP_SUPPORTED_SHAPES,
            Self::ConfidentialEddsa => &CONFIDENTIAL_EDDSA_SHAPES,
        }
    }

    pub fn supports(self, shape: Shape) -> bool {
        match self {
            Self::ConfidentialSigner => shape.is_supported(),
            Self::ConfidentialEddsa => shape.is_confidential_eddsa(),
        }
    }

    /// The cheapest of [`Self::shapes`] that holds `n_in` inputs and `n_out`
    /// outputs.
    pub fn canonical_shape(self, n_in: usize, n_out: usize) -> Result<Shape, TransactionError> {
        self.shapes()
            .iter()
            .copied()
            .find(|s| n_in <= s.n_inputs() && n_out <= s.n_outputs())
            .ok_or(TransactionError::UnsupportedShape { n_in, n_out })
    }
}

/// Whether some transact rail has keys for the shape.
pub(crate) fn is_transact_shape(shape: Shape) -> bool {
    shape.is_supported() || shape.is_confidential_eddsa()
}

/// Notes a wallet spend selects at most. Selection pads with random dummies,
/// so the cheapest shape holding this many notes still fits one transaction
/// with two encrypted outputs, inputs from every allowed tree, an owner
/// signer other than the payer and an SPL withdrawal; the next wider shape
/// does not. A wider balance merges first.
pub const MAX_SPEND_INPUTS: usize = 40;

/// Shapes automatic selection may pick: every supported shape, in proving
/// cost order, so the first one that fits is the cheapest.
pub fn auto_shapes() -> impl Iterator<Item = Shape> {
    SPP_SUPPORTED_SHAPES.into_iter()
}

/// The first of [`auto_shapes`] that holds `n_in` inputs and `n_out` outputs,
/// which is the cheapest to prove.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signer_rail_needs_every_owner_to_sign() {
        let owner = Address::new_from_array([1; 32]);
        let relayer = Address::new_from_array([2; 32]);
        assert_eq!(
            TransactRail::select(&[owner], &[relayer, owner]),
            TransactRail::ConfidentialSigner
        );
        assert_eq!(
            TransactRail::select(&[owner], &[relayer]),
            TransactRail::ConfidentialEddsa
        );
        assert_eq!(
            TransactRail::select(&[], &[relayer]),
            TransactRail::ConfidentialSigner
        );
    }

    #[test]
    fn each_rail_picks_the_cheapest_shape_of_its_own_list() {
        assert_eq!(
            TransactRail::ConfidentialSigner
                .canonical_shape(1, 2)
                .unwrap(),
            Shape::new(1, 2)
        );
        assert_eq!(
            TransactRail::ConfidentialEddsa
                .canonical_shape(1, 2)
                .unwrap(),
            Shape::IN2_OUT8
        );
        assert_eq!(
            TransactRail::ConfidentialEddsa
                .canonical_shape(17, 9)
                .unwrap(),
            Shape::new(24, 16)
        );
        assert!(matches!(
            TransactRail::ConfidentialEddsa.canonical_shape(49, 2),
            Err(TransactionError::UnsupportedShape { n_in: 49, n_out: 2 })
        ));
        assert!(TransactRail::ConfidentialEddsa.supports(Shape::new(48, 16)));
        assert!(!TransactRail::ConfidentialSigner.supports(Shape::new(48, 16)));
    }
}
