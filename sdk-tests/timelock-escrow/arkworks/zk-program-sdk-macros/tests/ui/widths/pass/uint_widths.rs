use zk_program_sdk::circuit::Uint;

fn main() {
    let amount = Uint::<64>::zero();
    let total = Uint::<64>::sum::<66, 3>(&[amount.clone(), amount.clone(), amount.clone()]);
    let product = amount.mul::<128>(&amount);
    let _ = (amount.add::<65>(&amount), total, product, amount.widen::<253>());
}
