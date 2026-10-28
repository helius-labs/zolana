#[derive(spr_program::ClientInputs)]
struct Bad {
    #[client(unknown)]
    field: u64,
}
fn main() {}
