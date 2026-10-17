use zolana_program::circuit::Field;

use crate::harness::{
    field::{field, HALF_ABOVE, HALF_BELOW, MODULUS_MINUS_1, TWO_POW_64},
    fixture::Named,
};

pub const X: &str = "12345678901234567890123456789012345678901234567890123456789012345678901234567";
const INVERSE_OF_X: &str =
    "12961863221634289924873179978725306227518033856377288862855027918193545695444";
const INVERSE_OF_3: &str =
    "14592161914559516814830937163504850059032242933610689562465469457717205663745";
const INVERSE_OF_TWO_POW_64: &str =
    "16662651760482593750343275155358532940078388361286693648211298903031153094221";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub x: &'static str,
    pub inverse: &'static str,
}

impl Named for Vector {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Vector {
    pub fn fields(&self) -> (Field, Field) {
        (field(self.x), field(self.inverse))
    }
}

pub const VALID: [Vector; 7] = [
    Vector {
        name: "1 / 1 = 1",
        x: "1",
        inverse: "1",
    },
    Vector {
        name: "1 / (p - 1) = p - 1",
        x: MODULUS_MINUS_1,
        inverse: MODULUS_MINUS_1,
    },
    Vector {
        name: "1 / 2 = (p + 1) / 2",
        x: "2",
        inverse: HALF_ABOVE,
    },
    Vector {
        name: "1 / ((p + 1) / 2) = 2",
        x: HALF_ABOVE,
        inverse: "2",
    },
    Vector {
        name: "1 / 3",
        x: "3",
        inverse: INVERSE_OF_3,
    },
    Vector {
        name: "1 / 2^64",
        x: TWO_POW_64,
        inverse: INVERSE_OF_TWO_POW_64,
    },
    Vector {
        name: "1 / x",
        x: X,
        inverse: INVERSE_OF_X,
    },
];

pub const INVALID: [Vector; 5] = [
    Vector {
        name: "1 / 2 = 2",
        x: "2",
        inverse: "2",
    },
    Vector {
        name: "1 / 2 = (p - 1) / 2",
        x: "2",
        inverse: HALF_BELOW,
    },
    Vector {
        name: "1 / 1 = 0",
        x: "1",
        inverse: "0",
    },
    Vector {
        name: "1 / x = x",
        x: X,
        inverse: X,
    },
    Vector {
        name: "1 / (p - 1) = 1",
        x: MODULUS_MINUS_1,
        inverse: "1",
    },
];

pub const ZERO: [Vector; 3] = [
    Vector {
        name: "1 / 0 = 0",
        x: "0",
        inverse: "0",
    },
    Vector {
        name: "1 / 0 = 1",
        x: "0",
        inverse: "1",
    },
    Vector {
        name: "1 / 0 = p - 1",
        x: "0",
        inverse: MODULUS_MINUS_1,
    },
];
