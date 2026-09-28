use zk_program_sdk::circuit::Field;

use crate::harness::{
    field::{field, HALF_ABOVE, MODULUS_MINUS_1},
    fixture::Named,
};

const X: &str = "12345678901234567890123456789012345678901234567890123456789012345678901234567";
const MINUS_X: &str =
    "9542563970604707332122948956244929409647129832525910886909191840896907261050";
const SEVEN_OVER_TWO: &str =
    "10944121435919637611123202872628637544274182200208017171849102093287904247812";
const SEVEN_OVER_X: &str =
    "3180071064082928585126636870048043238432779392976884665192378681051585885640";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub dividend: &'static str,
    pub divisor: &'static str,
    pub quotient: &'static str,
}

impl Named for Vector {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Vector {
    pub fn fields(&self) -> (Field, Field, Field) {
        (
            field(self.dividend),
            field(self.divisor),
            field(self.quotient),
        )
    }
}

pub const VALID: [Vector; 8] = [
    Vector {
        name: "0 / 1 = 0",
        dividend: "0",
        divisor: "1",
        quotient: "0",
    },
    Vector {
        name: "7 / 1 = 7",
        dividend: "7",
        divisor: "1",
        quotient: "7",
    },
    Vector {
        name: "1 / 2 = (p + 1) / 2",
        dividend: "1",
        divisor: "2",
        quotient: HALF_ABOVE,
    },
    Vector {
        name: "6 / 3 = 2",
        dividend: "6",
        divisor: "3",
        quotient: "2",
    },
    Vector {
        name: "7 / 2 = (p + 7) / 2",
        dividend: "7",
        divisor: "2",
        quotient: SEVEN_OVER_TWO,
    },
    Vector {
        name: "x / (p - 1) = -x",
        dividend: X,
        divisor: MODULUS_MINUS_1,
        quotient: MINUS_X,
    },
    Vector {
        name: "7 / x",
        dividend: "7",
        divisor: X,
        quotient: SEVEN_OVER_X,
    },
    Vector {
        name: "x / x = 1",
        dividend: X,
        divisor: X,
        quotient: "1",
    },
];

pub const INVALID: [Vector; 5] = [
    Vector {
        name: "7 / 2 = 3",
        dividend: "7",
        divisor: "2",
        quotient: "3",
    },
    Vector {
        name: "7 / 2 = 4",
        dividend: "7",
        divisor: "2",
        quotient: "4",
    },
    Vector {
        name: "6 / 3 = 3",
        dividend: "6",
        divisor: "3",
        quotient: "3",
    },
    Vector {
        name: "x / x = 0",
        dividend: X,
        divisor: X,
        quotient: "0",
    },
    Vector {
        name: "0 / x = x",
        dividend: "0",
        divisor: X,
        quotient: X,
    },
];

pub const ZERO: [Vector; 3] = [
    Vector {
        name: "0 / 0 = 0",
        dividend: "0",
        divisor: "0",
        quotient: "0",
    },
    Vector {
        name: "1 / 0 = 0",
        dividend: "1",
        divisor: "0",
        quotient: "0",
    },
    Vector {
        name: "x / 0 = 1",
        dividend: X,
        divisor: "0",
        quotient: "1",
    },
];
