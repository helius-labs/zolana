use zolana_program::circuit::Field;

use crate::harness::{
    field::{field, HALF_ABOVE, MODULUS_MINUS_1, TWO_POW_64},
    fixture::{Named, Visited},
};

const X: &str = "12345678901234567890123456789012345678901234567890123456789012345678901234567";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Single {
    pub name: &'static str,
    pub x: &'static str,
}

impl Named for Single {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Single {
    pub fn field(&self) -> Field {
        field(self.x)
    }

    pub fn bit(&self) -> bool {
        self.x == "1"
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pair {
    pub name: &'static str,
    pub a: &'static str,
    pub b: &'static str,
}

impl Named for Pair {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Pair {
    pub fn fields(&self) -> (Field, Field) {
        (field(self.a), field(self.b))
    }

    pub fn bits(&self) -> (bool, bool) {
        (self.a == "1", self.b == "1")
    }

    pub fn row(&self) -> usize {
        let (a, b) = self.bits();
        2 * usize::from(a) + usize::from(b)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Triple {
    pub name: &'static str,
    pub condition: bool,
    pub if_true: bool,
    pub if_false: bool,
}

impl Named for Triple {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Triple {
    pub fn fields(&self) -> (Field, Field, Field) {
        (
            Field::from(self.condition),
            Field::from(self.if_true),
            Field::from(self.if_false),
        )
    }

    pub fn selected(&self) -> bool {
        if self.condition {
            self.if_true
        } else {
            self.if_false
        }
    }
}

pub fn per_flags<T>(value: impl Fn(&[bool]) -> T) -> Visited<T> {
    FLAGS
        .iter()
        .map(|(name, flags)| (*name, value(flags)))
        .collect()
}

pub const BITS: [Single; 2] = [Single { name: "0", x: "0" }, Single { name: "1", x: "1" }];

pub const NON_BOOLEAN: [Single; 5] = [
    Single { name: "2", x: "2" },
    Single {
        name: "p - 1",
        x: MODULUS_MINUS_1,
    },
    Single {
        name: "(p + 1) / 2",
        x: HALF_ABOVE,
    },
    Single {
        name: "2^64",
        x: TWO_POW_64,
    },
    Single { name: "x", x: X },
];

pub const WRONG_CLAIMS: [Single; 3] = [
    Single { name: "2", x: "2" },
    Single {
        name: "p - 1",
        x: MODULUS_MINUS_1,
    },
    Single { name: "x", x: X },
];

pub const BOOLEAN_PAIRS: [Pair; 4] = [
    Pair {
        name: "0, 0",
        a: "0",
        b: "0",
    },
    Pair {
        name: "0, 1",
        a: "0",
        b: "1",
    },
    Pair {
        name: "1, 0",
        a: "1",
        b: "0",
    },
    Pair {
        name: "1, 1",
        a: "1",
        b: "1",
    },
];

pub const NON_BOOLEAN_PAIRS: [Pair; 5] = [
    Pair {
        name: "2, 0",
        a: "2",
        b: "0",
    },
    Pair {
        name: "1, 2",
        a: "1",
        b: "2",
    },
    Pair {
        name: "p - 1, 1",
        a: MODULUS_MINUS_1,
        b: "1",
    },
    Pair {
        name: "(p + 1) / 2, (p + 1) / 2",
        a: HALF_ABOVE,
        b: HALF_ABOVE,
    },
    Pair {
        name: "2^64, 0",
        a: TWO_POW_64,
        b: "0",
    },
];

pub const TRIPLES: [Triple; 8] = [
    Triple {
        name: "0 ? 0 : 0",
        condition: false,
        if_true: false,
        if_false: false,
    },
    Triple {
        name: "0 ? 0 : 1",
        condition: false,
        if_true: false,
        if_false: true,
    },
    Triple {
        name: "0 ? 1 : 0",
        condition: false,
        if_true: true,
        if_false: false,
    },
    Triple {
        name: "0 ? 1 : 1",
        condition: false,
        if_true: true,
        if_false: true,
    },
    Triple {
        name: "1 ? 0 : 0",
        condition: true,
        if_true: false,
        if_false: false,
    },
    Triple {
        name: "1 ? 0 : 1",
        condition: true,
        if_true: false,
        if_false: true,
    },
    Triple {
        name: "1 ? 1 : 0",
        condition: true,
        if_true: true,
        if_false: false,
    },
    Triple {
        name: "1 ? 1 : 1",
        condition: true,
        if_true: true,
        if_false: true,
    },
];

/// Every flag combination of lengths 0 to 3, named by its flags.
pub const FLAGS: [(&str, &[bool]); 15] = [
    ("[]", &[]),
    ("[0]", &[false]),
    ("[1]", &[true]),
    ("[0, 0]", &[false, false]),
    ("[0, 1]", &[false, true]),
    ("[1, 0]", &[true, false]),
    ("[1, 1]", &[true, true]),
    ("[0, 0, 0]", &[false, false, false]),
    ("[0, 0, 1]", &[false, false, true]),
    ("[0, 1, 0]", &[false, true, false]),
    ("[0, 1, 1]", &[false, true, true]),
    ("[1, 0, 0]", &[true, false, false]),
    ("[1, 0, 1]", &[true, false, true]),
    ("[1, 1, 0]", &[true, true, false]),
    ("[1, 1, 1]", &[true, true, true]),
];

/// Non-boolean flags whose sum is the sum `all` compares against: only the
/// booleanity checks refuse the claim that all are set.
pub const DECEPTIVE_ALL: (&str, [&str; 3]) = ("all over [2, 0, 1] sums to 3", ["2", "0", "1"]);

/// Non-boolean flags that sum to 0 although one is 1: only the booleanity
/// checks refuse the claim that none is set.
pub const DECEPTIVE_ANY: (&str, [&str; 3]) = (
    "any over [1, p - 1, 0] sums to 0",
    ["1", MODULUS_MINUS_1, "0"],
);
