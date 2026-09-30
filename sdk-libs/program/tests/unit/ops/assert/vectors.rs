use zolana_program::circuit::Field;

use crate::harness::{
    field::{field, HALF_ABOVE, HALF_BELOW, MODULUS_MINUS_1, TWO_POW_253, TWO_POW_64},
    fixture::Named,
};

pub const X: &str = "12345678901234567890123456789012345678901234567890123456789012345678901234567";
pub const MINUS_X: &str =
    "9542563970604707332122948956244929409647129832525910886909191840896907261050";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pair {
    pub name: &'static str,
    pub left: &'static str,
    pub right: &'static str,
}

impl Named for Pair {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Pair {
    pub fn fields(&self) -> (Field, Field) {
        (field(self.left), field(self.right))
    }
}

pub const EQUAL: [Pair; 5] = [
    Pair {
        name: "0 = 0",
        left: "0",
        right: "0",
    },
    Pair {
        name: "1 = 1",
        left: "1",
        right: "1",
    },
    Pair {
        name: "p - 1 = p - 1",
        left: MODULUS_MINUS_1,
        right: MODULUS_MINUS_1,
    },
    Pair {
        name: "2^64 = 2^64",
        left: TWO_POW_64,
        right: TWO_POW_64,
    },
    Pair {
        name: "x = x",
        left: X,
        right: X,
    },
];

pub const DIFFERENT: [Pair; 7] = [
    Pair {
        name: "0 != 1",
        left: "0",
        right: "1",
    },
    Pair {
        name: "1 != 0",
        left: "1",
        right: "0",
    },
    Pair {
        name: "0 != p - 1",
        left: "0",
        right: MODULUS_MINUS_1,
    },
    Pair {
        name: "(p - 1) / 2 != (p + 1) / 2",
        left: HALF_BELOW,
        right: HALF_ABOVE,
    },
    Pair {
        name: "2^253 != 2^64",
        left: TWO_POW_253,
        right: TWO_POW_64,
    },
    Pair {
        name: "x != -x",
        left: X,
        right: MINUS_X,
    },
    Pair {
        name: "1 != 2",
        left: "1",
        right: "2",
    },
];

pub const LENGTH: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arrays {
    pub name: &'static str,
    pub left: [&'static str; LENGTH],
    pub right: [&'static str; LENGTH],
    pub equal: bool,
}

impl Named for Arrays {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Arrays {
    pub fn fields(&self) -> ([Field; LENGTH], [Field; LENGTH]) {
        (self.left.map(field), self.right.map(field))
    }
}

pub const ARRAYS: [Arrays; 6] = [
    Arrays {
        name: "every element equal",
        left: ["0", MODULUS_MINUS_1, X],
        right: ["0", MODULUS_MINUS_1, X],
        equal: true,
    },
    Arrays {
        name: "the first element differs",
        left: ["1", MODULUS_MINUS_1, X],
        right: ["0", MODULUS_MINUS_1, X],
        equal: false,
    },
    Arrays {
        name: "the middle element differs",
        left: ["0", HALF_BELOW, X],
        right: ["0", HALF_ABOVE, X],
        equal: false,
    },
    Arrays {
        name: "the last element differs",
        left: ["0", MODULUS_MINUS_1, X],
        right: ["0", MODULUS_MINUS_1, MINUS_X],
        equal: false,
    },
    Arrays {
        name: "every element differs",
        left: ["0", "1", "2"],
        right: ["1", "2", "0"],
        equal: false,
    },
    Arrays {
        name: "the elements are swapped",
        left: ["0", "1", "0"],
        right: ["1", "0", "0"],
        equal: false,
    },
];
