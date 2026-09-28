use zk_program_sdk::circuit::Field;

use crate::harness::{
    field::{field, MODULUS_MINUS_1, TWO_POW_64},
    fixture::Named,
};

pub const X: &str = "12345678901234567890123456789012345678901234567890123456789012345678901234567";
const X_TO_THE_5: &str =
    "19253285033322315980140865145630249767841245781829655751618254459690793645612";

pub const BASES: [&str; 6] = ["0", "1", "2", MODULUS_MINUS_1, TWO_POW_64, X];
pub const EXPONENTS: [u64; 8] = [0, 1, 2, 3, 5, 1 << 32, 1 << 63, u64::MAX];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub x: &'static str,
    pub power: &'static str,
}

impl Named for Vector {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Vector {
    pub fn fields(&self) -> (Field, Field) {
        (field(self.x), field(self.power))
    }

    pub fn inputs(&self) -> [(&'static str, &'static str); 2] {
        [("x", self.x), ("power", self.power)]
    }
}

pub const VALID: [Vector; 5] = [
    Vector {
        name: "0^5 = 0",
        x: "0",
        power: "0",
    },
    Vector {
        name: "1^5 = 1",
        x: "1",
        power: "1",
    },
    Vector {
        name: "2^5 = 32",
        x: "2",
        power: "32",
    },
    Vector {
        name: "(p - 1)^5 = p - 1",
        x: MODULUS_MINUS_1,
        power: MODULUS_MINUS_1,
    },
    Vector {
        name: "x^5",
        x: X,
        power: X_TO_THE_5,
    },
];

pub const INVALID: [Vector; 5] = [
    Vector {
        name: "2^5 = 10",
        x: "2",
        power: "10",
    },
    Vector {
        name: "2^5 = 25",
        x: "2",
        power: "25",
    },
    Vector {
        name: "(p - 1)^5 = 1",
        x: MODULUS_MINUS_1,
        power: "1",
    },
    Vector {
        name: "0^5 = 1",
        x: "0",
        power: "1",
    },
    Vector {
        name: "x^5 = x",
        x: X,
        power: X,
    },
];
