use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use reqwest::{Client, Url};
use serde::Deserialize;

use super::auth::get_access_token;

const GCS_JSON_API: &str = "https://storage.googleapis.com/storage/v1/b/";

#[derive(Clone, Debug)]
pub(crate) struct GcsClient {
    http: Client,
}

#[derive(Debug, Deserialize)]
struct ListResponse {
    #[serde(default)]
    items: Vec<ListedObject>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListedObject {
    name: String,
}

impl Default for GcsClient {
    fn default() -> Self {
        Self {
            http: Client::new(),
        }
    }
}

impl GcsClient {
    pub(crate) async fn download(&self, bucket: &str, object: &str) -> Result<Bytes> {
        let token = get_access_token().await?;
        let response = self
            .http
            .get(object_url(bucket, object)?)
            .bearer_auth(token)
            .send()
            .await
            .with_context(|| format!("Failed to download GCS object {bucket}/{object}"))?
            .error_for_status()
            .with_context(|| format!("GCS rejected download of {bucket}/{object}"))?;
        response
            .bytes()
            .await
            .with_context(|| format!("Failed to read GCS object {bucket}/{object}"))
    }

    pub(crate) async fn list(&self, bucket: &str, prefix: &str) -> Result<Vec<String>> {
        let token = get_access_token().await?;
        let url = collection_url(bucket)?;
        let mut page_token: Option<String> = None;
        let mut objects = Vec::new();

        loop {
            let mut request = self.http.get(url.clone()).bearer_auth(&token);
            if !prefix.is_empty() {
                request = request.query(&[("prefix", prefix)]);
            }
            if let Some(token) = page_token.as_deref() {
                request = request.query(&[("pageToken", token)]);
            }
            let page = request
                .send()
                .await
                .with_context(|| format!("Failed to list GCS bucket {bucket}"))?
                .error_for_status()
                .with_context(|| format!("GCS rejected listing bucket {bucket}"))?
                .json::<ListResponse>()
                .await
                .with_context(|| format!("Failed to decode listing for GCS bucket {bucket}"))?;
            objects.extend(page.items.into_iter().map(|object| object.name));
            page_token = page.next_page_token;
            if page_token.is_none() {
                return Ok(objects);
            }
        }
    }

    pub(crate) async fn delete(&self, bucket: &str, object: &str) -> Result<()> {
        let token = get_access_token().await?;
        self.http
            .delete(object_metadata_url(bucket, object)?)
            .bearer_auth(token)
            .send()
            .await
            .with_context(|| format!("Failed to delete GCS object {bucket}/{object}"))?
            .error_for_status()
            .with_context(|| format!("GCS rejected deletion of {bucket}/{object}"))?;
        Ok(())
    }
}

fn collection_url(bucket: &str) -> Result<Url> {
    let mut url = Url::parse(GCS_JSON_API)?;
    url.path_segments_mut()
        .map_err(|_| anyhow!("GCS API URL cannot contain path segments"))?
        .pop_if_empty()
        .push(bucket)
        .push("o");
    Ok(url)
}

fn object_metadata_url(bucket: &str, object: &str) -> Result<Url> {
    let mut url = collection_url(bucket)?;
    url.path_segments_mut()
        .map_err(|_| anyhow!("GCS API URL cannot contain path segments"))?
        .push(object);
    Ok(url)
}

fn object_url(bucket: &str, object: &str) -> Result<Url> {
    let mut url = object_metadata_url(bucket, object)?;
    url.query_pairs_mut().append_pair("alt", "media");
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_url_encodes_bucket_and_object_as_path_segments() {
        let url = object_url("test bucket", "snapshots/1.bin").unwrap();
        assert_eq!(
            url.as_str(),
            "https://storage.googleapis.com/storage/v1/b/test%20bucket/o/snapshots%2F1.bin?alt=media"
        );
    }

    #[test]
    fn list_response_accepts_empty_and_paginated_pages() {
        let empty: ListResponse = serde_json::from_str("{}").unwrap();
        assert!(empty.items.is_empty());
        assert!(empty.next_page_token.is_none());

        let page: ListResponse = serde_json::from_str(
            r#"{"items":[{"name":"snapshots/1.bin"}],"nextPageToken":"next"}"#,
        )
        .unwrap();
        assert_eq!(page.items[0].name, "snapshots/1.bin");
        assert_eq!(page.next_page_token.as_deref(), Some("next"));
    }
}
