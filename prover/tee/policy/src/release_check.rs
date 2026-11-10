//! Checks every deployed backend of a prover generation before its release
//! part is relied on: each attests through the SDK's prover client under the
//! generation's PCRs, answers an encrypted proving-key check, and refuses a
//! plaintext proof request; all hold one HPKE key, since a release copies one
//! seed to every region.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use spr_client::AsyncProverClient;
use spr_prover_tee::TeePolicy;

/// How long a backend may take to refuse a plaintext proof request.
const PLAINTEXT_TIMEOUT: Duration = Duration::from_secs(30);

/// The one HPKE key every backend at `urls` attests with under `policy`.
pub async fn check(policy: &TeePolicy, urls: &[String]) -> Result<[u8; 32]> {
    let mut keys = Vec::with_capacity(urls.len());
    for url in urls {
        let prover = AsyncProverClient::new(url.clone()).with_tee(policy.clone());
        let attested = prover
            .attest()
            .await
            .with_context(|| format!("{url} does not attest under the generation's PCRs"))?;
        prover
            .check_proving_keys()
            .await
            .with_context(|| format!("{url} fails the encrypted proving-key check"))?;
        refuses_plaintext(url).await?;
        keys.push((url.as_str(), attested.hpke_public_key));
    }
    one_key(&keys)
}

/// The key all backends share; an error naming each backend's key otherwise.
fn one_key(keys: &[(&str, [u8; 32])]) -> Result<[u8; 32]> {
    let Some((_, first)) = keys.first() else {
        bail!("no backend to check");
    };
    if keys.iter().any(|(_, key)| key != first) {
        let held: Vec<_> = keys
            .iter()
            .map(|(url, key)| format!("{url} {}", hex::encode(key)))
            .collect();
        bail!("the backends hold different keys: {}", held.join(", "));
    }
    Ok(*first)
}

/// Fails unless the backend answers a plaintext proof request with 400
/// `tee_required`: one that proves it would take witnesses in the clear.
async fn refuses_plaintext(url: &str) -> Result<()> {
    let response = reqwest::Client::new()
        .post(format!("{}/prove", url.trim_end_matches('/')))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body("{}")
        .timeout(PLAINTEXT_TIMEOUT)
        .send()
        .await
        .with_context(|| format!("{url} is unreachable"))?;
    let status = response.status().as_u16();
    let code = response
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|body| body.get("code")?.as_str().map(str::to_owned));
    if (status, code.as_deref()) != (400, Some("tee_required")) {
        bail!(
            "{url} answers a plaintext proof request with {status} {}, not 400 tee_required",
            code.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    #[test]
    fn the_backends_must_share_one_key() {
        assert_eq!(one_key(&[("a", [1; 32]), ("b", [1; 32])]).unwrap(), [1; 32]);
        let error = one_key(&[("a", [1; 32]), ("b", [2; 32])]).unwrap_err();
        assert!(error.to_string().contains("different keys"));
        assert!(one_key(&[]).is_err());
    }

    /// A backend answering every request with `status` and `body`.
    async fn backend(status: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        url
    }

    #[tokio::test]
    async fn a_backend_must_refuse_plaintext_with_tee_required() {
        let refusing = backend(
            "400 Bad Request",
            r#"{"code":"tee_required","message":"TEE request rejected"}"#,
        )
        .await;
        refuses_plaintext(&refusing).await.unwrap();
        refuses_plaintext(&format!("{refusing}/")).await.unwrap();
        for (status, body) in [
            ("200 OK", r#"{"proof":"..."}"#),
            ("400 Bad Request", r#"{"code":"bad_request"}"#),
            ("502 Bad Gateway", "<html></html>"),
        ] {
            let url = backend(status, body).await;
            let error = refuses_plaintext(&url).await.unwrap_err();
            assert!(
                error.to_string().contains("not 400 tee_required"),
                "{error}"
            );
        }
    }
}
