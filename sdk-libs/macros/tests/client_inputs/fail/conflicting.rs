#[derive(spr_program::ClientInputs)]
struct Bad {
    #[client(nested, nested)]
    field: u64,
}
fn main() {}
