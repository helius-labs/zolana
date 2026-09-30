use zolana_program::conversion::ProofInput;

#[derive(ProofInput)]
struct Amounts {
    #[max_len(2)]
    amounts: Vec<u64>,
}

fn main() {}
