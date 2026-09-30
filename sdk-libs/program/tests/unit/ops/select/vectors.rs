use zolana_program::circuit::Field;

use super::super::assert::vectors::{MINUS_X, X};
use crate::harness::{
    field::{field, HALF_ABOVE, HALF_BELOW, MODULUS_MINUS_1, TWO_POW_253, TWO_POW_64},
    fixture::Named,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Branches {
    pub name: &'static str,
    pub if_true: &'static str,
    pub if_false: &'static str,
}

impl Named for Branches {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Branches {
    pub fn fields(&self) -> (Field, Field) {
        (field(self.if_true), field(self.if_false))
    }

    pub fn chosen(&self, condition: bool) -> Field {
        field(if condition {
            self.if_true
        } else {
            self.if_false
        })
    }

    pub fn claim(&self, condition: bool) -> (bool, Field, Field, Field) {
        let (if_true, if_false) = self.fields();
        (condition, if_true, if_false, self.chosen(condition))
    }
}

pub const BRANCHES: [Branches; 7] = [
    Branches {
        name: "0 or 0",
        if_true: "0",
        if_false: "0",
    },
    Branches {
        name: "0 or 1",
        if_true: "0",
        if_false: "1",
    },
    Branches {
        name: "1 or 0",
        if_true: "1",
        if_false: "0",
    },
    Branches {
        name: "p - 1 or 1",
        if_true: MODULUS_MINUS_1,
        if_false: "1",
    },
    Branches {
        name: "(p - 1) / 2 or (p + 1) / 2",
        if_true: HALF_BELOW,
        if_false: HALF_ABOVE,
    },
    Branches {
        name: "2^253 or 2^64",
        if_true: TWO_POW_253,
        if_false: TWO_POW_64,
    },
    Branches {
        name: "x or -x",
        if_true: X,
        if_false: MINUS_X,
    },
];

pub const CONDITIONS: [bool; 2] = [false, true];

pub const LENGTH: usize = 3;

pub fn arrays() -> ([Field; LENGTH], [Field; LENGTH]) {
    (
        [X, "0", MODULUS_MINUS_1].map(field),
        [MINUS_X, "1", MODULUS_MINUS_1].map(field),
    )
}
