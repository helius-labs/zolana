use solana_address::Address;
use spr_program::circuit::PublicInputs;

#[derive(Clone, PublicInputs)]
struct PayoutPublicInputs {
    amount: u64,
    destination: Address,
}

fn main() {}
