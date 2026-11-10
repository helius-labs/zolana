/// Masks known secrets, and any `api-key=` query value, in text bound for a log.
#[derive(Clone, Debug, Default)]
pub struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    pub fn new(secrets: Vec<String>) -> Self {
        let mut secrets: Vec<String> = secrets.into_iter().filter(|s| !s.is_empty()).collect();
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        Self { secrets }
    }

    pub fn apply(&self, text: &str) -> String {
        let mut text = self.secrets.iter().fold(text.to_string(), |text, secret| {
            text.replace(secret.as_str(), "redacted")
        });
        let marker = "api-key=";
        let mut start = 0;
        while let Some(found) = text[start..].to_ascii_lowercase().find(marker) {
            let value_start = start + found + marker.len();
            let value_len = text[value_start..]
                .find(|c: char| !(c.is_ascii_alphanumeric() || "-._~%+/=".contains(c)))
                .unwrap_or(text.len() - value_start);
            text.replace_range(value_start..value_start + value_len, "redacted");
            start = value_start + "redacted".len();
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_secrets_are_masked_anywhere() {
        let redactor = Redactor::new(vec!["s3cret".into(), String::new()]);
        assert_eq!(
            redactor.apply("prover said s3cret twice: s3cret"),
            "prover said redacted twice: redacted"
        );
    }

    #[test]
    fn unknown_api_key_values_are_masked() {
        let redactor = Redactor::default();
        assert_eq!(
            redactor.apply("error sending request for url (https://x.example/v1/spr/prove?API-KEY=abc-123&jobId=1)"),
            "error sending request for url (https://x.example/v1/spr/prove?API-KEY=redacted&jobId=1)"
        );
        assert_eq!(
            redactor.apply("a?api-key=one b?api-key=two"),
            "a?api-key=redacted b?api-key=redacted"
        );
    }

    #[test]
    fn text_without_secrets_is_unchanged() {
        let redactor = Redactor::new(vec!["s3cret".into()]);
        assert_eq!(redactor.apply("indexer timeout"), "indexer timeout");
    }
}
