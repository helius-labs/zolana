#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Shape {
    n_inputs: usize,
    n_outputs: usize,
}

impl Shape {
    pub const IN1_OUT2: Self = Self {
        n_inputs: 1,
        n_outputs: 2,
    };
    pub const IN1_OUT4: Self = Self {
        n_inputs: 1,
        n_outputs: 4,
    };
    pub const IN1_OUT8: Self = Self {
        n_inputs: 1,
        n_outputs: 8,
    };
    pub const IN1_OUT16: Self = Self {
        n_inputs: 1,
        n_outputs: 16,
    };
    pub const IN2_OUT2: Self = Self {
        n_inputs: 2,
        n_outputs: 2,
    };
    pub const IN2_OUT4: Self = Self {
        n_inputs: 2,
        n_outputs: 4,
    };
    pub const IN2_OUT8: Self = Self {
        n_inputs: 2,
        n_outputs: 8,
    };
    pub const IN2_OUT16: Self = Self {
        n_inputs: 2,
        n_outputs: 16,
    };
    pub const IN3_OUT2: Self = Self {
        n_inputs: 3,
        n_outputs: 2,
    };
    pub const IN3_OUT4: Self = Self {
        n_inputs: 3,
        n_outputs: 4,
    };
    pub const IN3_OUT8: Self = Self {
        n_inputs: 3,
        n_outputs: 8,
    };
    pub const IN4_OUT2: Self = Self {
        n_inputs: 4,
        n_outputs: 2,
    };
    pub const IN4_OUT4: Self = Self {
        n_inputs: 4,
        n_outputs: 4,
    };
    pub const IN4_OUT8: Self = Self {
        n_inputs: 4,
        n_outputs: 8,
    };
    pub const IN4_OUT16: Self = Self {
        n_inputs: 4,
        n_outputs: 16,
    };
    pub const IN5_OUT2: Self = Self {
        n_inputs: 5,
        n_outputs: 2,
    };
    pub const IN5_OUT4: Self = Self {
        n_inputs: 5,
        n_outputs: 4,
    };
    pub const IN5_OUT8: Self = Self {
        n_inputs: 5,
        n_outputs: 8,
    };
    pub const IN5_OUT16: Self = Self {
        n_inputs: 5,
        n_outputs: 16,
    };
    pub const IN6_OUT2: Self = Self {
        n_inputs: 6,
        n_outputs: 2,
    };
    pub const IN6_OUT4: Self = Self {
        n_inputs: 6,
        n_outputs: 4,
    };
    pub const IN6_OUT8: Self = Self {
        n_inputs: 6,
        n_outputs: 8,
    };
    pub const IN8_OUT2: Self = Self {
        n_inputs: 8,
        n_outputs: 2,
    };
    pub const IN8_OUT4: Self = Self {
        n_inputs: 8,
        n_outputs: 4,
    };
    pub const IN8_OUT8: Self = Self {
        n_inputs: 8,
        n_outputs: 8,
    };
    pub const IN8_OUT16: Self = Self {
        n_inputs: 8,
        n_outputs: 16,
    };
    pub const IN12_OUT2: Self = Self {
        n_inputs: 12,
        n_outputs: 2,
    };
    pub const IN12_OUT4: Self = Self {
        n_inputs: 12,
        n_outputs: 4,
    };
    pub const IN12_OUT8: Self = Self {
        n_inputs: 12,
        n_outputs: 8,
    };
    pub const IN16_OUT2: Self = Self {
        n_inputs: 16,
        n_outputs: 2,
    };
    pub const IN16_OUT4: Self = Self {
        n_inputs: 16,
        n_outputs: 4,
    };
    pub const IN16_OUT8: Self = Self {
        n_inputs: 16,
        n_outputs: 8,
    };
    pub const IN24_OUT2: Self = Self {
        n_inputs: 24,
        n_outputs: 2,
    };
    pub const IN24_OUT4: Self = Self {
        n_inputs: 24,
        n_outputs: 4,
    };
    pub const IN32_OUT2: Self = Self {
        n_inputs: 32,
        n_outputs: 2,
    };
    pub const IN40_OUT2: Self = Self {
        n_inputs: 40,
        n_outputs: 2,
    };
    pub const IN48_OUT2: Self = Self {
        n_inputs: 48,
        n_outputs: 2,
    };
    pub const IN51_OUT2: Self = Self {
        n_inputs: 51,
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

    /// Whether the SPP prover has keys for this shape, see [`SPP_SUPPORTED_SHAPES`].
    pub const fn is_supported(self) -> bool {
        let mut shapes: &[Shape] = &SPP_SUPPORTED_SHAPES;
        while let Some((shape, rest)) = shapes.split_first() {
            if shape.n_inputs == self.n_inputs && shape.n_outputs == self.n_outputs {
                return true;
            }
            shapes = rest;
        }
        false
    }

    /// Whether the ring authority rail has keys for this shape: square, with a
    /// width from [`RING_AUTHORITY_WIDTHS`].
    pub const fn is_ring_authority(self) -> bool {
        if self.n_inputs != self.n_outputs {
            return false;
        }
        let mut widths: &[usize] = &RING_AUTHORITY_WIDTHS;
        while let Some((width, rest)) = widths.split_first() {
            if *width == self.n_inputs {
                return true;
            }
            widths = rest;
        }
        false
    }
}

/// Square widths the ring authority rail has keys for, ascending.
pub const RING_AUTHORITY_WIDTHS: [usize; 2] = [2, 4];

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
pub const MAX_SIGNERS: usize = 29;

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

/// Shapes the SPP prover has keys for, ordered by proving cost so the first
/// shape that fits is the cheapest. Slot-signed transactions declare their
/// exact shape (they do not pad), so they validate against this full set.
pub const SPP_SUPPORTED_SHAPES: [Shape; 38] = [
    Shape::IN1_OUT2,
    Shape::IN1_OUT4,
    Shape::IN1_OUT8,
    Shape::IN2_OUT2,
    Shape::IN2_OUT4,
    Shape::IN1_OUT16,
    Shape::IN2_OUT8,
    Shape::IN3_OUT2,
    Shape::IN3_OUT4,
    Shape::IN2_OUT16,
    Shape::IN3_OUT8,
    Shape::IN4_OUT2,
    Shape::IN4_OUT4,
    Shape::IN4_OUT8,
    Shape::IN5_OUT2,
    Shape::IN5_OUT4,
    Shape::IN4_OUT16,
    Shape::IN5_OUT8,
    Shape::IN6_OUT2,
    Shape::IN6_OUT4,
    Shape::IN5_OUT16,
    Shape::IN6_OUT8,
    Shape::IN8_OUT2,
    Shape::IN8_OUT4,
    Shape::IN8_OUT8,
    Shape::IN8_OUT16,
    Shape::IN12_OUT2,
    Shape::IN12_OUT4,
    Shape::IN12_OUT8,
    Shape::IN16_OUT2,
    Shape::IN16_OUT4,
    Shape::IN16_OUT8,
    Shape::IN24_OUT2,
    Shape::IN24_OUT4,
    Shape::IN32_OUT2,
    Shape::IN40_OUT2,
    Shape::IN48_OUT2,
    Shape::IN51_OUT2,
];
