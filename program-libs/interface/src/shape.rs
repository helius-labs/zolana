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

/// Shapes the SPP prover has keys for. Slot-signed transactions declare their
/// exact shape (they do not pad), so they validate against this full set rather
/// than the fixed padded-transfer shape ([`Shape::IN2_OUT3`]).
pub const SPP_SUPPORTED_SHAPES: [Shape; 10] = [
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
