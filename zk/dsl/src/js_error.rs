use wasm_bindgen::JsValue;

use crate::{CircuitError, ProverError, SourceLocation};

#[doc(hidden)]
pub fn js_error(name: &str, message: &str, location: SourceLocation) -> JsValue {
    let error = js_sys::Error::new(message);
    error.set_name(name);
    let _ = js_sys::Reflect::set(
        &error,
        &JsValue::from_str("location"),
        &JsValue::from_str(&location.to_string()),
    );
    error.into()
}

impl From<CircuitError> for JsValue {
    fn from(error: CircuitError) -> Self {
        js_error(error.name(), &error.to_string(), error.location())
    }
}

impl From<ProverError> for JsValue {
    fn from(error: ProverError) -> Self {
        js_error(error.name(), &error.to_string(), error.location())
    }
}
