use zk_program_sdk::circuit::Field;

use crate::harness::field::{
    field, HALF_ABOVE, HALF_BELOW, MODULUS, MODULUS_MINUS_1, MODULUS_MINUS_2, TWO_POW_253,
    TWO_POW_64, TWO_POW_64_MINUS_1,
};

const X: &str = "12345678901234567890123456789012345678901234567890123456789012345678901234567";
const MINUS_X: &str =
    "9542563970604707332122948956244929409647129832525910886909191840896907261050";
const TWO_POW_254_MINUS_MODULUS: &str =
    "7059779437489773633646340506914701874769131765994106666166191815402473914367";
const TWO_POW_254_MINUS_MODULUS_PLUS_1: &str =
    "7059779437489773633646340506914701874769131765994106666166191815402473914368";
const TWO_POW_64_PLUS_1: &str = "18446744073709551617";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub left: &'static str,
    pub right: &'static str,
    pub sum: &'static str,
}

impl Vector {
    pub fn fields(&self) -> (Field, Field, Field) {
        (field(self.left), field(self.right), field(self.sum))
    }

    pub fn inputs(&self) -> [(&'static str, &'static str); 3] {
        [
            ("left", self.left),
            ("right", self.right),
            ("sum", self.sum),
        ]
    }
}

pub const VALID: [Vector; 8] = [
    Vector {
        name: "0 + 0 = 0",
        left: "0",
        right: "0",
        sum: "0",
    },
    Vector {
        name: "0 + x = x",
        left: "0",
        right: X,
        sum: X,
    },
    Vector {
        name: "1 + (p - 1) = 0",
        left: "1",
        right: MODULUS_MINUS_1,
        sum: "0",
    },
    Vector {
        name: "(p - 1) + (p - 1) = p - 2",
        left: MODULUS_MINUS_1,
        right: MODULUS_MINUS_1,
        sum: MODULUS_MINUS_2,
    },
    Vector {
        name: "(p - 1) / 2 + (p + 1) / 2 = 0",
        left: HALF_BELOW,
        right: HALF_ABOVE,
        sum: "0",
    },
    Vector {
        name: "(2^64 - 1) + 1 = 2^64",
        left: TWO_POW_64_MINUS_1,
        right: "1",
        sum: TWO_POW_64,
    },
    Vector {
        name: "2^253 + 2^253 = 2^254 - p",
        left: TWO_POW_253,
        right: TWO_POW_253,
        sum: TWO_POW_254_MINUS_MODULUS,
    },
    Vector {
        name: "x + (-x) = 0",
        left: X,
        right: MINUS_X,
        sum: "0",
    },
];

pub const INVALID: [Vector; 7] = [
    Vector {
        name: "1 + 2 = 4",
        left: "1",
        right: "2",
        sum: "4",
    },
    Vector {
        name: "1 + (p - 1) = p - 1",
        left: "1",
        right: MODULUS_MINUS_1,
        sum: MODULUS_MINUS_1,
    },
    Vector {
        name: "(2^64 - 1) + 1 = 2^64 - 1",
        left: TWO_POW_64_MINUS_1,
        right: "1",
        sum: TWO_POW_64_MINUS_1,
    },
    Vector {
        name: "(2^64 - 1) + 1 = 2^64 + 1",
        left: TWO_POW_64_MINUS_1,
        right: "1",
        sum: TWO_POW_64_PLUS_1,
    },
    Vector {
        name: "2^253 + 2^253 = (2^254 - p) + 1",
        left: TWO_POW_253,
        right: TWO_POW_253,
        sum: TWO_POW_254_MINUS_MODULUS_PLUS_1,
    },
    Vector {
        name: "5 + 7 = 5",
        left: "5",
        right: "7",
        sum: "5",
    },
    Vector {
        name: "3 + 4 = 0",
        left: "3",
        right: "4",
        sum: "0",
    },
];

pub const NON_CANONICAL: Vector = Vector {
    name: "(p - 1) + 1 = p",
    left: MODULUS_MINUS_1,
    right: "1",
    sum: MODULUS,
};
