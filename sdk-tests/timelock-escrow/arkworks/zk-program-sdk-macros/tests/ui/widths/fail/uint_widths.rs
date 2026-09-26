use zk_program_sdk::circuit::Uint;

fn main() {
    let empty = Uint::<0>::zero();
    let amount = Uint::<64>::zero();
    let wrapped = amount.add::<64>(&amount);
    let truncated = amount.mul::<100>(&amount);
    let widened = amount.narrow::<64>("not narrower");
    let ordered = Uint::<253>::zero().is_less_than(&Uint::<253>::zero());
    let _ = (empty, wrapped, truncated, widened, ordered);
}
