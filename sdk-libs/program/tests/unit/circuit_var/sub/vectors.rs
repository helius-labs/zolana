use zolana_program::circuit::Field;

use crate::harness::{
    field::{
        field, HALF_ABOVE, HALF_BELOW, MODULUS, MODULUS_MINUS_1, TWO_POW_253, TWO_POW_64,
        TWO_POW_64_MINUS_1,
    },
    fixture::Named,
};

const X: &str = "12345678901234567890123456789012345678901234567890123456789012345678901234567";
const MINUS_X: &str =
    "9542563970604707332122948956244929409647129832525910886909191840896907261050";
const TWO_X: &str = "2803114930629860558000507832767416269254104735364212569879820504781993973517";
const MODULUS_MINUS_TWO_POW_253: &str =
    "7414231717174750794300032619171286606889616317210963838766006185586667290625";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub left: &'static str,
    pub right: &'static str,
    pub difference: &'static str,
}

impl Named for Vector {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Vector {
    pub fn fields(&self) -> (Field, Field, Field) {
        (field(self.left), field(self.right), field(self.difference))
    }

    pub fn inputs(&self) -> [(&'static str, &'static str); 3] {
        [
            ("left", self.left),
            ("right", self.right),
            ("difference", self.difference),
        ]
    }
}

pub const VALID: [Vector; 9] = [
    Vector {
        name: "0 - 0 = 0",
        left: "0",
        right: "0",
        difference: "0",
    },
    Vector {
        name: "x - 0 = x",
        left: X,
        right: "0",
        difference: X,
    },
    Vector {
        name: "0 - 1 = p - 1",
        left: "0",
        right: "1",
        difference: MODULUS_MINUS_1,
    },
    Vector {
        name: "1 - (p - 1) = 2",
        left: "1",
        right: MODULUS_MINUS_1,
        difference: "2",
    },
    Vector {
        name: "(p - 1) - (p - 1) = 0",
        left: MODULUS_MINUS_1,
        right: MODULUS_MINUS_1,
        difference: "0",
    },
    Vector {
        name: "(p + 1) / 2 - (p - 1) / 2 = 1",
        left: HALF_ABOVE,
        right: HALF_BELOW,
        difference: "1",
    },
    Vector {
        name: "2^64 - 1 = 2^64 - 1",
        left: TWO_POW_64,
        right: "1",
        difference: TWO_POW_64_MINUS_1,
    },
    Vector {
        name: "0 - 2^253 = p - 2^253",
        left: "0",
        right: TWO_POW_253,
        difference: MODULUS_MINUS_TWO_POW_253,
    },
    Vector {
        name: "x - (-x) = 2x",
        left: X,
        right: MINUS_X,
        difference: TWO_X,
    },
];

pub const INVALID: [Vector; 7] = [
    Vector {
        name: "5 - 3 = 3",
        left: "5",
        right: "3",
        difference: "3",
    },
    Vector {
        name: "0 - 1 = 1",
        left: "0",
        right: "1",
        difference: "1",
    },
    Vector {
        name: "2 - 1 = p - 1",
        left: "2",
        right: "1",
        difference: MODULUS_MINUS_1,
    },
    Vector {
        name: "2^64 - 1 = 2^64",
        left: TWO_POW_64,
        right: "1",
        difference: TWO_POW_64,
    },
    Vector {
        name: "1 - (p - 1) = 0",
        left: "1",
        right: MODULUS_MINUS_1,
        difference: "0",
    },
    Vector {
        name: "x - (-x) = 0",
        left: X,
        right: MINUS_X,
        difference: "0",
    },
    Vector {
        name: "(p - 1) - (p - 1) = p - 1",
        left: MODULUS_MINUS_1,
        right: MODULUS_MINUS_1,
        difference: MODULUS_MINUS_1,
    },
];

pub const NON_CANONICAL: Vector = Vector {
    name: "1 - 1 = p",
    left: "1",
    right: "1",
    difference: MODULUS,
};
