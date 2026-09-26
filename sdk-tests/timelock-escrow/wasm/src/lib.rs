use timelock_escrow_arkworks as _;
use wasm_bindgen::prelude::*;
use zk_program_sdk as _;

#[cfg(feature = "threads")]
pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}
