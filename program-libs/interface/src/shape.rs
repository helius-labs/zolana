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
    /// Consolidation shape. Sized against the tightest consumer rather than a
    /// bare `transact`: a custom ring adds its own accounts, data and a second
    /// signer, and at today's recipient ciphertext length that path tops out
    /// near 38 inputs. Measure with `cargo run -p xtask -- max-shape`.
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
}

/// Largest input count in `shapes`; sizes the program's fixed input buffers.
pub const fn max_inputs(mut shapes: &[Shape]) -> usize {
    let mut max = 0;
    while let Some((shape, rest)) = shapes.split_first() {
        if shape.n_inputs > max {
            max = shape.n_inputs;
        }
        shapes = rest;
    }
    max
}

/// Largest output count in `shapes`; sizes the program's fixed output buffers.
pub const fn max_outputs(mut shapes: &[Shape]) -> usize {
    let mut max = 0;
    while let Some((shape, rest)) = shapes.split_first() {
        if shape.n_outputs > max {
            max = shape.n_outputs;
        }
        shapes = rest;
    }
    max
}

/// Shapes the SPP prover has keys for. Slot-signed transactions declare their
/// exact shape (they do not pad), so they validate against this full set rather
/// than the fixed padded-transfer shape ([`Shape::IN2_OUT3`]).
///
/// This is the *validation* set. It is deliberately not the set a client
/// searches when no shape is declared: see [`SPP_AUTO_SHAPES`].
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

/// Shapes a client may pick automatically when the caller declares none.
///
/// Excludes the large consolidation shape. `canonical_shape` is a smallest-fit
/// search, so including it would silently route a six-input transfer to a
/// 36-input circuit -- roughly twenty times the constraints for no benefit. A
/// caller that wants it must ask for it by name.
pub const SPP_AUTO_SHAPES: [Shape; 10] = [
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
];
