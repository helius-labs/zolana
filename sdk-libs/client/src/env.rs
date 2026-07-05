//! Env-with-fallback URL resolution shared by the connection presets.

/// Trimmed value of `var`, or `default` when unset or blank.
pub(crate) fn env_url(var: &str, default: &str) -> String {
    match std::env::var(var) {
        Ok(url) if !url.trim().is_empty() => url.trim().to_string(),
        _ => default.to_string(),
    }
}
