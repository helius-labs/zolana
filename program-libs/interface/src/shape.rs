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

    const fn is(&self, other: Shape) -> bool {
        self.n_inputs == other.n_inputs && self.n_outputs == other.n_outputs
    }

    pub const fn n_inputs(&self) -> usize {
        self.n_inputs
    }

    pub const fn n_outputs(&self) -> usize {
        self.n_outputs
    }
}

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

/// The consolidation shape: supported, but only reached by declaring it.
pub const SPP_CONSOLIDATION_SHAPE: Shape = Shape::IN36_OUT2;

/// [`SPP_SUPPORTED_SHAPES`] minus [`SPP_CONSOLIDATION_SHAPE`]: the shapes
/// automatic selection may pick.
pub const SPP_AUTO_SHAPES: [Shape; SPP_SUPPORTED_SHAPES.len() - 1] = auto_shapes();

const fn auto_shapes() -> [Shape; SPP_SUPPORTED_SHAPES.len() - 1] {
    let mut auto = [SPP_CONSOLIDATION_SHAPE; SPP_SUPPORTED_SHAPES.len() - 1];
    let mut written = 0;
    let mut remaining: &[Shape] = &SPP_SUPPORTED_SHAPES;
    while let Some((shape, rest)) = remaining.split_first() {
        if !shape.is(SPP_CONSOLIDATION_SHAPE) {
            assert!(
                written < auto.len(),
                "SPP_SUPPORTED_SHAPES must list the consolidation shape exactly once"
            );
            auto[written] = *shape;
            written += 1;
        }
        remaining = rest;
    }
    assert!(
        written == auto.len(),
        "SPP_SUPPORTED_SHAPES must list the consolidation shape exactly once"
    );
    auto
}
