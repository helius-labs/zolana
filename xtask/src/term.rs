//! Minimal ANSI colour for gate summaries. Colour only when the stream is a
//! terminal and NO_COLOR is unset, so CI logs and pipes stay plain.

use std::io::IsTerminal;

#[derive(Clone, Copy)]
pub struct Style {
    enabled: bool,
}

impl Style {
    pub fn stdout() -> Self {
        Self::for_terminal(std::io::stdout().is_terminal())
    }

    pub fn stderr() -> Self {
        Self::for_terminal(std::io::stderr().is_terminal())
    }

    fn for_terminal(is_terminal: bool) -> Self {
        Self {
            enabled: is_terminal && std::env::var_os("NO_COLOR").is_none(),
        }
    }

    fn wrap(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn green(&self, text: &str) -> String {
        self.wrap("32", text)
    }

    pub fn red(&self, text: &str) -> String {
        self.wrap("31", text)
    }

    pub fn yellow(&self, text: &str) -> String {
        self.wrap("33", text)
    }
}
