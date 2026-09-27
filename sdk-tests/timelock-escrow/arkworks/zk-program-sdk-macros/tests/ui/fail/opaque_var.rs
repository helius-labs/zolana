use zk_program_sdk::circuit::{constant, CircuitSystem, CircuitVar, Field};

fn division(left: CircuitVar, right: &CircuitVar) -> CircuitVar {
    let quotient = left.clone() / right;
    let remainder = &quotient % Field::from(2u64);
    let mut total = remainder;
    total /= right.clone();
    total
}

fn comparison(left: &CircuitVar, right: &CircuitVar) -> bool {
    left == right || left < right
}

fn native_value(var: &CircuitVar) -> Field {
    var.value().unwrap()
}

fn allocation(cs: CircuitSystem) -> CircuitVar {
    CircuitVar::new_witness(cs, || Ok(Field::from(1u64))).unwrap()
}

fn pattern(var: CircuitVar) -> Field {
    match var {
        CircuitVar::Constant(value) => value,
        _ => Field::from(0u64),
    }
}

fn main() {
    let one = constant(1u64);
    let _ = (
        division(one.clone(), &one),
        comparison(&one, &one),
        native_value(&one),
        allocation(CircuitSystem::None),
        pattern(one),
    );
}
