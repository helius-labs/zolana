use std::{
    env,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

static TOKEN_CACHE: Lazy<Mutex<Option<AccessToken>>> = Lazy::new(|| Mutex::new(None));

#[derive(Clone, Debug)]
struct AccessToken {
    value: String,
    refresh_at: Instant,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default = "default_token_lifetime")]
    expires_in: u64,
}

pub(crate) async fn get_access_token() -> Result<String> {
    {
        let cache = TOKEN_CACHE.lock().await;
        if let Some(token) = cache
            .as_ref()
            .filter(|token| token.refresh_at > Instant::now())
        {
            return Ok(token.value.clone());
        }
    }

    let token = fetch_access_token().await?;
    let mut cache = TOKEN_CACHE.lock().await;
    if let Some(current) = cache
        .as_ref()
        .filter(|current| current.refresh_at > Instant::now())
    {
        return Ok(current.value.clone());
    }
    let value = token.value.clone();
    *cache = Some(token);
    Ok(value)
}

async fn fetch_access_token() -> Result<AccessToken> {
    if let Some(credentials_json) = service_account_credentials().await? {
        get_token_from_service_account(&credentials_json).await
    } else {
        get_token_from_metadata_service()
            .await
            .context("Failed to get an access token from the GCP metadata service")
    }
}

async fn service_account_credentials() -> Result<Option<String>> {
    for name in ["SERVICE_ACCOUNT", "GOOGLE_APPLICATION_CREDENTIALS"] {
        if let Some(path) = env::var_os(name) {
            let path = PathBuf::from(path);
            return tokio::fs::read_to_string(&path)
                .await
                .with_context(|| format!("Failed to read {name} file {}", path.display()))
                .map(Some);
        }
    }
    for name in [
        "SERVICE_ACCOUNT_JSON",
        "GOOGLE_APPLICATION_CREDENTIALS_JSON",
    ] {
        if let Some(json) = env::var_os(name) {
            return json
                .into_string()
                .map(Some)
                .map_err(|_| anyhow!("{name} is not valid UTF-8"));
        }
    }
    Ok(None)
}

async fn get_token_from_metadata_service() -> Result<AccessToken> {
    let response = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?
        .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
        .header("Metadata-Flavor", "Google")
        .send()
        .await?
        .error_for_status()
        .context("GCP metadata service rejected the token request")?
        .json::<TokenResponse>()
        .await
        .context("Failed to decode the GCP metadata token response")?;
    Ok(cacheable_token(response))
}

async fn get_token_from_service_account(credentials_json: &str) -> Result<AccessToken> {
    #[derive(Debug, Deserialize)]
    struct ServiceAccount {
        client_email: String,
        private_key: String,
        token_uri: String,
    }

    #[derive(Debug, Serialize)]
    struct Claims {
        iss: String,
        scope: String,
        aud: String,
        exp: u64,
        iat: u64,
    }

    let service_account: ServiceAccount = serde_json::from_str(credentials_json)
        .context("Failed to parse service account credentials")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock is before UNIX_EPOCH")?
        .as_secs();
    let claims = Claims {
        iss: service_account.client_email,
        scope: "https://www.googleapis.com/auth/devstorage.read_write".to_string(),
        aud: service_account.token_uri.clone(),
        exp: now + default_token_lifetime(),
        iat: now,
    };
    let key = EncodingKey::from_rsa_pem(service_account.private_key.as_bytes())
        .context("Failed to parse service account private key")?;
    let jwt = encode(&Header::new(Algorithm::RS256), &claims, &key)
        .context("Failed to sign service account token request")?;
    let response = Client::new()
        .post(&service_account.token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt),
        ])
        .send()
        .await
        .context("Failed to exchange service account credentials for an access token")?
        .error_for_status()
        .context("Google OAuth rejected the service account token request")?
        .json::<TokenResponse>()
        .await
        .context("Failed to decode the Google OAuth token response")?;
    Ok(cacheable_token(response))
}

fn cacheable_token(response: TokenResponse) -> AccessToken {
    const REFRESH_MARGIN_SECONDS: u64 = 60;

    AccessToken {
        value: response.access_token,
        refresh_at: Instant::now()
            + Duration::from_secs(
                response
                    .expires_in
                    .saturating_sub(REFRESH_MARGIN_SECONDS)
                    .max(1),
            ),
    }
}

const fn default_token_lifetime() -> u64 {
    3600
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_cache_refreshes_before_expiration() {
        let token = cacheable_token(TokenResponse {
            access_token: "token".to_string(),
            expires_in: 120,
        });
        let remaining = token.refresh_at.saturating_duration_since(Instant::now());
        assert!(remaining <= Duration::from_secs(60));
        assert!(remaining > Duration::from_secs(55));
    }
}
