use zolana_program::circuit::Field;

use crate::harness::{
    field::{field, HALF_ABOVE, HALF_BELOW, MODULUS, MODULUS_MINUS_1, TWO_POW_253, TWO_POW_64},
    fixture::Named,
};

pub const X: &str = "12345678901234567890123456789012345678901234567890123456789012345678901234567";
const MINUS_X: &str =
    "9542563970604707332122948956244929409647129832525910886909191840896907261050";
const MODULUS_MINUS_TWO_POW_253: &str =
    "7414231717174750794300032619171286606889616317210963838766006185586667290625";
const MODULUS_MINUS_TWO_POW_64: &str =
    "21888242871839275222246405745257275088548364400416034343679757442502098944001";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub value: &'static str,
    pub negation: &'static str,
}

impl Named for Vector {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Vector {
    pub fn fields(&self) -> (Field, Field) {
        (field(self.value), field(self.negation))
    }

    pub fn inputs(&self) -> [(&'static str, &'static str); 2] {
        [("value", self.value), ("negation", self.negation)]
    }
}

pub const VALID: [Vector; 7] = [
    Vector {
        name: "-0 = 0",
        value: "0",
        negation: "0",
    },
    Vector {
        name: "-1 = p - 1",
        value: "1",
        negation: MODULUS_MINUS_1,
    },
    Vector {
        name: "-(p - 1) = 1",
        value: MODULUS_MINUS_1,
        negation: "1",
    },
    Vector {
        name: "-((p - 1) / 2) = (p + 1) / 2",
        value: HALF_BELOW,
        negation: HALF_ABOVE,
    },
    Vector {
        name: "-2^64 = p - 2^64",
        value: TWO_POW_64,
        negation: MODULUS_MINUS_TWO_POW_64,
    },
    Vector {
        name: "-2^253 = p - 2^253",
        value: TWO_POW_253,
        negation: MODULUS_MINUS_TWO_POW_253,
    },
    Vector {
        name: "-x = p - x",
        value: X,
        negation: MINUS_X,
    },
];

pub const INVALID: [Vector; 6] = [
    Vector {
        name: "-1 = 1",
        value: "1",
        negation: "1",
    },
    Vector {
        name: "-0 = p - 1",
        value: "0",
        negation: MODULUS_MINUS_1,
    },
    Vector {
        name: "-x = x",
        value: X,
        negation: X,
    },
    Vector {
        name: "-((p - 1) / 2) = (p - 1) / 2",
        value: HALF_BELOW,
        negation: HALF_BELOW,
    },
    Vector {
        name: "-2^64 = 2^64",
        value: TWO_POW_64,
        negation: TWO_POW_64,
    },
    Vector {
        name: "-(p - 1) = 0",
        value: MODULUS_MINUS_1,
        negation: "0",
    },
];

pub const NON_CANONICAL: Vector = Vector {
    name: "-0 = p",
    value: "0",
    negation: MODULUS,
};
