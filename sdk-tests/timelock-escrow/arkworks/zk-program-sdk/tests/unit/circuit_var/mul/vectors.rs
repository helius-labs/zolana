use zk_program_sdk::circuit::Field;

use crate::harness::{
    field::{field, HALF_ABOVE, MODULUS, MODULUS_MINUS_1, TWO_POW_64},
    fixture::Named,
};

const X: &str = "12345678901234567890123456789012345678901234567890123456789012345678901234567";
const MINUS_X: &str =
    "9542563970604707332122948956244929409647129832525910886909191840896907261050";
const X_SQUARED: &str =
    "13519967323926219064349002855361446920711564754053834125674227036826663504960";
const TWO_POW_128: &str = "340282366920938463463374607431768211456";
const TWO_POW_256_MOD_P: &str =
    "6350874878119819312338956282401532410528162663560392320966563075034087161851";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub left: &'static str,
    pub right: &'static str,
    pub product: &'static str,
}

impl Named for Vector {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Vector {
    pub fn fields(&self) -> (Field, Field, Field) {
        (field(self.left), field(self.right), field(self.product))
    }

    pub fn inputs(&self) -> [(&'static str, &'static str); 3] {
        [
            ("left", self.left),
            ("right", self.right),
            ("product", self.product),
        ]
    }
}

pub const VALID: [Vector; 9] = [
    Vector {
        name: "0 * 0 = 0",
        left: "0",
        right: "0",
        product: "0",
    },
    Vector {
        name: "0 * x = 0",
        left: "0",
        right: X,
        product: "0",
    },
    Vector {
        name: "1 * x = x",
        left: "1",
        right: X,
        product: X,
    },
    Vector {
        name: "(p - 1) * (p - 1) = 1",
        left: MODULUS_MINUS_1,
        right: MODULUS_MINUS_1,
        product: "1",
    },
    Vector {
        name: "x * (p - 1) = -x",
        left: X,
        right: MODULUS_MINUS_1,
        product: MINUS_X,
    },
    Vector {
        name: "2 * (p + 1) / 2 = 1",
        left: "2",
        right: HALF_ABOVE,
        product: "1",
    },
    Vector {
        name: "2^64 * 2^64 = 2^128",
        left: TWO_POW_64,
        right: TWO_POW_64,
        product: TWO_POW_128,
    },
    Vector {
        name: "2^128 * 2^128 = 2^256 mod p",
        left: TWO_POW_128,
        right: TWO_POW_128,
        product: TWO_POW_256_MOD_P,
    },
    Vector {
        name: "x * x = x^2",
        left: X,
        right: X,
        product: X_SQUARED,
    },
];

pub const INVALID: [Vector; 7] = [
    Vector {
        name: "2 * 3 = 5",
        left: "2",
        right: "3",
        product: "5",
    },
    Vector {
        name: "2 * 3 = 7",
        left: "2",
        right: "3",
        product: "7",
    },
    Vector {
        name: "0 * 0 = 1",
        left: "0",
        right: "0",
        product: "1",
    },
    Vector {
        name: "x * 0 = x",
        left: X,
        right: "0",
        product: X,
    },
    Vector {
        name: "(p - 1) * (p - 1) = p - 1",
        left: MODULUS_MINUS_1,
        right: MODULUS_MINUS_1,
        product: MODULUS_MINUS_1,
    },
    Vector {
        name: "2 * (p + 1) / 2 = 0",
        left: "2",
        right: HALF_ABOVE,
        product: "0",
    },
    Vector {
        name: "2^128 * 2^128 = 0",
        left: TWO_POW_128,
        right: TWO_POW_128,
        product: "0",
    },
];

pub const NON_CANONICAL: Vector = Vector {
    name: "1 * 0 = p",
    left: "1",
    right: "0",
    product: MODULUS,
};
