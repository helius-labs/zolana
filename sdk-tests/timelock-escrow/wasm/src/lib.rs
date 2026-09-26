use timelock_escrow_arkworks as _;
use wasm_bindgen::prelude::*;
use zk_program_sdk as _;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}
