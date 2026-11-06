#[derive(spr_program::ClientInputs)]
struct Bad {
    #[client(nested)]
    field: u64,
}
fn main() {}
