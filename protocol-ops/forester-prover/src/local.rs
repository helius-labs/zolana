use crate::{error::Result, key::ExpectedProvingKey, Error};
use std::{
    ffi::{c_char, CStr, CString},
    path::PathBuf,
};

unsafe extern "C" {
    fn ForesterProve(
        path: *const c_char,
        expected: *const c_char,
        body: *const c_char,
    ) -> *mut c_char;
    fn ForesterFree(value: *mut c_char);
}
pub(crate) struct LocalProver {
    keys: PathBuf,
}
impl LocalProver {
    pub fn new(keys: PathBuf) -> Self {
        Self { keys }
    }
    pub fn prove(&self, key: &ExpectedProvingKey, body: &str) -> Result<serde_json::Value> {
        let path = self.keys.join(&key.name);
        let path = path
            .to_str()
            .ok_or_else(|| Error::Prover("key path is not UTF-8".into()))?;
        let c_string = |value: &str| {
            CString::new(value).map_err(|_| Error::Prover("NUL in FFI argument".into()))
        };
        let path = c_string(path)?;
        let expected = c_string(&hex::encode(key.sha256))?;
        let body = c_string(body)?;
        // Arguments stay alive for the call. Go owns the returned C allocation,
        // which is copied before the matching exported free releases it.
        let raw = unsafe { ForesterProve(path.as_ptr(), expected.as_ptr(), body.as_ptr()) };
        if raw.is_null() {
            return Err(Error::Prover("gnark returned a null response".into()));
        }
        let proof_json_bytes = unsafe { CStr::from_ptr(raw).to_bytes().to_vec() };
        unsafe {
            ForesterFree(raw);
        }
        let value: serde_json::Value = serde_json::from_slice(&proof_json_bytes)?;
        if let Some(error) = value.get("error").and_then(serde_json::Value::as_str) {
            return Err(Error::Prover(error.into()));
        }
        Ok(value)
    }
}
