use std::{borrow::Cow, io};

use tracing_subscriber::EnvFilter;

const API_KEY_PARAM: &str = "api-key=";

/// Logs to stdout with every `api-key=` value redacted: an RPC error names its
/// URL, query string included.
pub fn setup() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(|| Redacting(io::stdout()))
        .try_init();
}

/// `text` with the value of every `api-key=` parameter replaced by `REDACTED`.
pub fn redact_api_keys(text: &str) -> Cow<'_, str> {
    if !text.contains(API_KEY_PARAM) {
        return Cow::Borrowed(text);
    }
    let mut redacted = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(API_KEY_PARAM) {
        let value = at + API_KEY_PARAM.len();
        redacted.push_str(&rest[..value]);
        redacted.push_str("REDACTED");
        let end = rest[value..]
            .find(|c: char| c.is_whitespace() || "&#\"'),<>\u{1b}".contains(c))
            .map_or(rest.len(), |len| value + len);
        rest = &rest[end..];
    }
    redacted.push_str(rest);
    Cow::Owned(redacted)
}

/// A writer that redacts each write. The fmt layer writes a whole event at once.
struct Redacting<W>(W);

impl<W: io::Write> io::Write for Redacting<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match std::str::from_utf8(buf) {
            Ok(text) => self.0.write_all(redact_api_keys(text).as_bytes())?,
            Err(_) => self.0.write_all(buf)?,
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn api_keys_are_redacted_wherever_a_url_appears() {
        for (text, expected) in [
            (
                "for url (https://devnet.helius-rpc.com/?api-key=1d9d-secret)",
                "for url (https://devnet.helius-rpc.com/?api-key=REDACTED)",
            ),
            (
                "a?api-key=one&cluster=devnet b?x=1&api-key=two c?api-key=three",
                "a?api-key=REDACTED&cluster=devnet b?x=1&api-key=REDACTED c?api-key=REDACTED",
            ),
            (
                "\u{1b}[3murl\u{1b}[0m=https://h/?api-key=k\u{1b}[0m done",
                "\u{1b}[3murl\u{1b}[0m=https://h/?api-key=REDACTED\u{1b}[0m done",
            ),
            ("no key here", "no key here"),
        ] {
            assert_eq!(redact_api_keys(text), expected);
        }
    }

    #[test]
    fn the_log_writer_redacts_what_it_writes() {
        let mut writer = Redacting(Vec::new());
        let line = b"error sending request for url (https://h/?api-key=secret)\n";
        assert_eq!(writer.write(line).unwrap(), line.len());
        assert_eq!(
            String::from_utf8(writer.0).unwrap(),
            "error sending request for url (https://h/?api-key=REDACTED)\n"
        );
    }
}
