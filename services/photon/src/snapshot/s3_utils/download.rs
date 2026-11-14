use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use async_stream::try_stream;
use bytes::Bytes;
use futures::Stream;
use s3::Bucket;

const RANGE_BYTES: u64 = 8 * 1024 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ATTEMPTS: u32 = 3;

async fn read_range(
    bucket: &Bucket,
    key: &str,
    start: u64,
    end: u64,
    length: u64,
    etag: &str,
) -> Result<Bytes> {
    // Finish the bounded GET before yielding, so indexing never holds its response open.
    let response =
        tokio::time::timeout(READ_TIMEOUT, bucket.get_object_range(key, start, Some(end)))
            .await
            .context("Snapshot range download timed out")??;
    ensure!(
        response.status_code() == 206,
        "Snapshot range returned HTTP {}",
        response.status_code()
    );
    let headers = response.headers();
    let expected_range = format!("bytes {start}-{end}/{length}");
    ensure!(
        headers.get("content-range") == Some(&expected_range),
        "Snapshot response has an unexpected Content-Range"
    );
    ensure!(
        headers.get("etag").map(String::as_str) == Some(etag),
        "Snapshot object ETag changed during download"
    );
    ensure!(
        response.as_slice().len() as u64 == end - start + 1,
        "Snapshot range body is incomplete"
    );
    Ok(response.into_bytes())
}

pub(crate) fn read_object<'a>(
    bucket: &'a Bucket,
    key: &'a str,
) -> impl Stream<Item = Result<Bytes>> + Send + 'a {
    try_stream! {
        let (head, status) = tokio::time::timeout(READ_TIMEOUT, bucket.head_object(key))
            .await.context("Snapshot object HEAD timed out")?
            .with_context(|| format!("Failed to inspect snapshot object {key}"))?;
        if status != 200 {
            Err::<(), _>(anyhow!("Snapshot object HEAD returned HTTP {status}"))?;
        }
        let length = head.content_length.context("Snapshot object has no content length")?;
        let length = u64::try_from(length)?;
        let etag = head.e_tag.context("Snapshot object has no ETag")?;
        let mut headers = bucket.extra_headers().clone();
        headers.insert(reqwest::header::IF_MATCH, etag.parse()?);
        let bucket = bucket.with_extra_headers(headers)?;
        let mut start = 0;

        while start < length {
            let end = start.saturating_add(RANGE_BYTES - 1).min(length - 1);
            let mut attempt = 0;
            let bytes = loop {
                attempt += 1;
                let result = read_range(&bucket, key, start, end, length, &etag).await;
                match result {
                    Ok(bytes) => break bytes,
                    Err(error) if attempt == MAX_ATTEMPTS => {
                        Err::<(), _>(error).with_context(|| format!(
                            "Failed to read snapshot object {key} bytes {start}-{end} after {attempt} attempts"
                        ))?;
                    }
                    Err(_) => tokio::time::sleep(Duration::from_secs(u64::from(attempt))).await,
                }
            };
            start = end + 1;
            yield bytes;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::R2DirectoryAdapter;
    use futures::{pin_mut, StreamExt};
    use s3::{creds::Credentials, Region};
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        thread::JoinHandle,
        time::Instant,
    };

    fn serve(responses: Vec<Vec<u8>>) -> (Bucket, Arc<AtomicUsize>, JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let count = Arc::new(AtomicUsize::new(0));
        let requests = count.clone();
        let handle = std::thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let deadline = Instant::now() + Duration::from_secs(15);
                    let (mut socket, _) = loop {
                        match listener.accept() {
                            Ok(connection) => break connection,
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                assert!(Instant::now() < deadline, "Expected another S3 request");
                                std::thread::sleep(Duration::from_millis(1));
                            }
                            Err(error) => panic!("{error}"),
                        }
                    };
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut request = String::new();
                    let mut reader = BufReader::new(&mut socket);
                    loop {
                        let mut line = String::new();
                        assert!(reader.read_line(&mut line).unwrap() > 0);
                        request.push_str(&line);
                        if line == "\r\n" {
                            break;
                        }
                    }
                    requests.fetch_add(1, Ordering::SeqCst);
                    socket.write_all(&response).unwrap();
                    request.to_ascii_lowercase()
                })
                .collect()
        });
        let credentials = Credentials::new(Some("test"), Some("test"), None, None, None).unwrap();
        let bucket = *Bucket::new(
            "bucket",
            Region::Custom {
                region: "us-east-1".into(),
                endpoint,
            },
            credentials,
        )
        .unwrap()
        .with_path_style();
        (bucket, count, handle)
    }

    fn head(length: usize) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n").into_bytes()
    }

    fn range(body: &[u8], content_range: &str, etag: &str) -> Vec<u8> {
        let mut response = format!("HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: {content_range}\r\nETag: {etag}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
        response.extend_from_slice(body);
        response
    }

    #[tokio::test]
    async fn finishes_each_range_before_yielding_and_retries_a_broken_body() {
        let size = RANGE_BYTES as usize;
        let body = (0..size + 3).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let content_range = format!("bytes 0-{}/{}", size - 1, body.len());
        let full = range(&body[..size], &content_range, "\"v1\"");
        let mut broken = full.clone();
        broken.truncate(broken.len() - size + 17);
        let (bucket, count, server) = serve(vec![
            head(body.len()),
            broken,
            full,
            range(
                &body[size..],
                &format!("bytes {size}-{}/{}", size + 2, body.len()),
                "\"v1\"",
            ),
        ]);
        let adapter = Arc::new(R2DirectoryAdapter {
            r2_bucket: bucket,
            r2_prefix: "snapshots".into(),
        });
        let chunks = R2DirectoryAdapter::read_file(adapter, "file".into()).await;
        pin_mut!(chunks);
        assert_eq!(
            chunks.next().await.unwrap().unwrap().as_ref(),
            &body[..size]
        );
        assert_eq!(count.load(Ordering::SeqCst), 3);
        assert_eq!(
            chunks.next().await.unwrap().unwrap().as_ref(),
            &body[size..]
        );
        assert!(chunks.next().await.is_none());
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("head /bucket/snapshots/file "));
        for request in &requests[1..] {
            assert!(request.contains("if-match: \"v1\"\r\n"));
        }
        assert!(requests[1].contains(&format!("range: bytes=0-{}\r\n", size - 1)));
        assert!(requests[2].contains(&format!("range: bytes=0-{}\r\n", size - 1)));
        assert!(requests[3].contains(&format!("range: bytes={size}-{}\r\n", size + 2)));
    }

    #[tokio::test]
    async fn exhausted_retries_never_yield_a_partial_range() {
        let mut broken = range(b"hello", "bytes 0-4/5", "\"v1\"");
        broken.truncate(broken.len() - 3);
        let (bucket, count, server) = serve(vec![head(5), broken.clone(), broken.clone(), broken]);
        let chunks = read_object(&bucket, "file");
        pin_mut!(chunks);
        let error = chunks.next().await.unwrap().unwrap_err();
        assert!(
            format!("{error:#}").contains("bytes 0-4 after 3 attempts"),
            "{error:#}"
        );
        assert!(chunks.next().await.is_none());
        server.join().unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn refuses_an_object_that_changes_after_head() {
        let changed = range(b"hello", "bytes 0-4/5", "\"v2\"");
        let (bucket, _, server) = serve(vec![head(5), changed.clone(), changed.clone(), changed]);
        let chunks = read_object(&bucket, "file");
        pin_mut!(chunks);
        let error = chunks.next().await.unwrap().unwrap_err();
        assert!(format!("{error:#}").contains("ETag changed"), "{error:#}");
        for request in &server.join().unwrap()[1..] {
            assert!(request.contains("if-match: \"v1\"\r\n"));
        }
    }

    #[tokio::test]
    async fn refuses_ignored_or_incorrect_ranges() {
        let ignored = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"v1\"\r\nConnection: close\r\n\r\nhello".to_vec();
        let wrong = range(b"hello", "bytes 1-5/6", "\"v1\"");
        for (response, expected_error) in [(ignored, "returned HTTP 200"), (wrong, "Content-Range")]
        {
            let (bucket, _, server) =
                serve(vec![head(5), response.clone(), response.clone(), response]);
            let chunks = read_object(&bucket, "file");
            pin_mut!(chunks);
            let error = chunks.next().await.unwrap().unwrap_err();
            assert!(format!("{error:#}").contains(expected_error), "{error:#}");
            server.join().unwrap();
        }
    }
}
