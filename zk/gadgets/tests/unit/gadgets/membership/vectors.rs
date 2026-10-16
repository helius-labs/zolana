use zolana_program::circuit::Field;

use super::fixtures::{is_in_fixture, AssertIn, IsIn};
use crate::harness::{
    field::{field, MODULUS_MINUS_1},
    fixture::Named,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub value: &'static str,
    pub set: [&'static str; 3],
    pub member: bool,
}

impl Named for Vector {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Vector {
    pub fn value(&self) -> Field {
        field(self.value)
    }

    pub fn set(&self) -> [Field; 3] {
        self.set.map(field)
    }

    pub fn is_in(&self) -> IsIn<3> {
        is_in_fixture(self.value(), self.set(), self.member)
    }

    pub fn flipped(&self) -> IsIn<3> {
        is_in_fixture(self.value(), self.set(), !self.member)
    }

    pub fn assert_in(&self) -> AssertIn<3> {
        AssertIn {
            value: self.value(),
            set: self.set(),
        }
    }
}

const fn vector(
    name: &'static str,
    value: &'static str,
    set: [&'static str; 3],
    member: bool,
) -> Vector {
    Vector {
        name,
        value,
        set,
        member,
    }
}

const ODD: [&str; 3] = ["3", "5", "7"];
const EDGES: [&str; 3] = [MODULUS_MINUS_1, MODULUS_MINUS_1, "0"];

pub const VECTORS: [Vector; 9] = [
    vector("5 is in {3, 5, 7}", "5", ODD, true),
    vector("3, the first member, is in {3, 5, 7}", "3", ODD, true),
    vector("7, the last member, is in {3, 5, 7}", "7", ODD, true),
    vector("4 is not in {3, 5, 7}", "4", ODD, false),
    vector("0 is not in {3, 5, 7}", "0", ODD, false),
    vector("p - 1 is not in {3, 5, 7}", MODULUS_MINUS_1, ODD, false),
    vector(
        "p - 1, twice a member, is in {p - 1, p - 1, 0}",
        MODULUS_MINUS_1,
        EDGES,
        true,
    ),
    vector("0 is in {p - 1, p - 1, 0}", "0", EDGES, true),
    vector("1 is not in {p - 1, p - 1, 0}", "1", EDGES, false),
];
