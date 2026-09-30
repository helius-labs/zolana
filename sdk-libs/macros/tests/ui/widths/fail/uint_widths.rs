use zolana_program::circuit::{Uint, U128};

fn main() {
    let empty = Uint::<0>::zero();
    let amount = Uint::<64>::zero();
    let wrapped = amount.add::<64>(&amount);
    let truncated = amount.mul::<100>(&amount);
    let squared = U128::zero().checked_mul(&U128::zero(), "fits in 128 bits");
    let ordered = Uint::<253>::zero().is_less_than(&Uint::<253>::zero());
    let _ = (empty, wrapped, truncated, squared, ordered);
}
