#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Shape {
    n_inputs: usize,
    n_outputs: usize,
}

impl Shape {
    pub const IN1_OUT1: Self = Self {
        n_inputs: 1,
        n_outputs: 1,
    };
    pub const IN1_OUT2: Self = Self {
        n_inputs: 1,
        n_outputs: 2,
    };
    pub const IN2_OUT2: Self = Self {
        n_inputs: 2,
        n_outputs: 2,
    };
    pub const IN2_OUT3: Self = Self {
        n_inputs: 2,
        n_outputs: 3,
    };
    pub const IN3_OUT3: Self = Self {
        n_inputs: 3,
        n_outputs: 3,
    };
    pub const IN4_OUT3: Self = Self {
        n_inputs: 4,
        n_outputs: 3,
    };
    pub const IN4_OUT4: Self = Self {
        n_inputs: 4,
        n_outputs: 4,
    };
    pub const IN5_OUT3: Self = Self {
        n_inputs: 5,
        n_outputs: 3,
    };
    pub const IN5_OUT4: Self = Self {
        n_inputs: 5,
        n_outputs: 4,
    };
    pub const IN1_OUT8: Self = Self {
        n_inputs: 1,
        n_outputs: 8,
    };
    pub const IN36_OUT2: Self = Self {
        n_inputs: 36,
        n_outputs: 2,
    };

    pub const fn new(n_inputs: usize, n_outputs: usize) -> Self {
        Self {
            n_inputs,
            n_outputs,
        }
    }

    pub const fn n_inputs(&self) -> usize {
        self.n_inputs
    }

    pub const fn n_outputs(&self) -> usize {
        self.n_outputs
    }

    /// Slots in the public signer vector on the signature-requiring rails:
    /// the payer followed by [`owner_signer_slots`] owner signers. The ring
    /// authority rail publishes a single slot instead.
    pub const fn signer_width(self) -> usize {
        owner_signer_slots(self.n_inputs) + 1
    }
}

/// Distinct addresses one transaction can carry, `solana_message::v1::MAX_ADDRESSES`.
pub const MAX_TRANSACTION_ADDRESSES: usize = 64;

/// Addresses every `transact` needs besides its nullifier PDAs and owner
/// signers: payer, input tree (the output tree may coincide with it), the
/// shielded-pool program and the system program.
pub const FIXED_TRANSACT_ADDRESSES: usize = 4;

/// Owner signer slots the public signer vector reserves for `n_inputs` inputs.
///
/// One per input, capped by the addresses a transaction has left after the
/// fixed accounts and one nullifier PDA per input. The circuit width has to be
/// the bound the program cannot rule out; PDA owners sign through CPI, so the
/// transaction signature cap does not lower it, and settlement accounts only
/// reduce the reachable count further.
pub const fn owner_signer_slots(n_inputs: usize) -> usize {
    let remaining = MAX_TRANSACTION_ADDRESSES.saturating_sub(FIXED_TRANSACT_ADDRESSES + n_inputs);
    if n_inputs < remaining {
        n_inputs
    } else {
        remaining
    }
}

/// Widest public signer vector over [`SPP_SUPPORTED_SHAPES`]; the program sizes
/// its fixed signer buffers from it.
pub const MAX_SIGNERS: usize = 25;

/// The buffer bounds hold for every supported shape, or the build fails.
const _: () = {
    let mut shapes: &[Shape] = &SPP_SUPPORTED_SHAPES;
    while let Some((shape, rest)) = shapes.split_first() {
        assert!(shape.signer_width() <= MAX_SIGNERS);
        assert!(shape.n_inputs <= crate::MAX_TRANSACT_INPUTS);
        assert!(shape.n_outputs <= crate::MAX_OUTPUTS);
        shapes = rest;
    }
};

/// Shapes the SPP prover has keys for. Slot-signed transactions declare their
/// exact shape (they do not pad), so they validate against this full set rather
/// than the fixed padded-transfer shape ([`Shape::IN2_OUT3`]).
pub const SPP_SUPPORTED_SHAPES: [Shape; 11] = [
    Shape::IN1_OUT1,
    Shape::IN1_OUT2,
    Shape::IN2_OUT2,
    Shape::IN2_OUT3,
    Shape::IN3_OUT3,
    Shape::IN4_OUT3,
    Shape::IN4_OUT4,
    Shape::IN5_OUT3,
    Shape::IN5_OUT4,
    Shape::IN1_OUT8,
    Shape::IN36_OUT2,
];
