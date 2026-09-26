use zk_program_sdk::{circuit, circuit::CircuitVar};

#[circuit]
fn violations(values: [CircuitVar; 2], flag: bool, maybe: Option<u64>) -> u64 {
    let first = if flag { 1u64 } else { 2u64 };
    if let Some(inner) = maybe {
        let _ = inner;
    }
    let second = match flag {
        true => 1u64,
        false => 2u64,
    };
    let third = match const { 1u64 } {
        value if value > 0 => value,
        _ => 0,
    };
    while flag {}
    loop {
        break;
    }
    for _ in values.iter() {
        continue;
    }
    let Some(fourth) = maybe else { return 0 };
    let fifth = flag && flag || flag;
    let sixth = [1u64, 2u64][0];
    let seventh: Vec<u64> = Vec::new();
    println!("{first}");
    first + second + third + fourth + u64::from(fifth) + sixth + seventh.len() as u64
}

fn main() {}
