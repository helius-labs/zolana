use crate::harness::field::{field, MODULUS_MINUS_1};
use zolana_program::circuit::Field;

pub fn items() -> [[Field; 3]; 4] {
    [
        [field("0"), field("1"), field(MODULUS_MINUS_1)],
        [field("3"), field("5"), field("7")],
        [field("9"); 3],
        [field("0"); 3],
    ]
}
pub fn invalid_indices() -> [Field; 4] {
    [
        field("3"),
        field("4"),
        field("18446744073709551616"),
        field(MODULUS_MINUS_1),
    ]
}
