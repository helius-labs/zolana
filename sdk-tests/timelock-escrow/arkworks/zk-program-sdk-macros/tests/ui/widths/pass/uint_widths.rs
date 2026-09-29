use zk_program_sdk::circuit::{Uint, U128, U64};

fn main() {
    let amount = U64::zero();
    let total = Uint::<64>::sum::<66, 3>(&[amount.clone(), amount.clone(), amount.clone()]);
    let product = amount.mul::<128>(&amount);
    let widened = U128::from(amount.clone());
    let narrowed = U64::try_from(widened.clone());
    let checked = (
        amount.checked_add(&amount, "fits in 64 bits"),
        amount.checked_mul(&amount, "fits in 64 bits"),
    );
    let _ = (amount.add::<65>(&amount), total, product, widened, narrowed, checked);
}
