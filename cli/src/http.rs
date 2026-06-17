use std::{
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpStream},
    process::Child,
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

pub(crate) fn wait_for_rpc_with_child(
    port: u16,
    timeout: Duration,
    child: &mut Child,
    label: &str,
) -> Result<()> {
    wait_until_with_child(timeout, child, label, || rpc_health(port))
}

pub(crate) fn wait_for_http_get_with_child(
    port: u16,
    path: &str,
    timeout: Duration,
    child: &mut Child,
    label: &str,
) -> Result<()> {
    wait_until_with_child(timeout, child, label, || {
        http_get_status(port, path)
            .map(|status| (200..300).contains(&status))
            .unwrap_or(false)
    })
}

pub(crate) fn wait_for_tcp_with_child(
    port: u16,
    timeout: Duration,
    child: &mut Child,
    label: &str,
) -> Result<()> {
    wait_until_with_child(timeout, child, label, || tcp_connect(port).is_ok())
}

fn wait_until_with_child<F>(
    timeout: Duration,
    child: &mut Child,
    label: &str,
    mut ready: F,
) -> Result<()>
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(status) = child.try_wait()? {
            bail!("{label} exited early with status {status}");
        }
        if ready() {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
    bail!("timed out after {} seconds", timeout.as_secs())
}

fn rpc_health(port: u16) -> bool {
    rpc_request(port, "getHealth")
        .ok()
        .and_then(|value| value.get("result").cloned())
        .and_then(|value| value.as_str().map(str::to_string))
        .as_deref()
        == Some("ok")
}

fn tcp_connect(port: u16) -> Result<()> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&address, Duration::from_secs(1))
        .map(|_| ())
        .map_err(Into::into)
}

fn rpc_request(port: u16, method: &str) -> Result<Value> {
    json_rpc_request(port, "/", method)
}

fn json_rpc_request(port: u16, path: &str, method: &str) -> Result<Value> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": [],
    })
    .to_string();
    let response = http_request(
        port,
        "POST",
        path,
        Some(("application/json", body.as_bytes())),
    )?;
    let status = http_status(&response).ok_or_else(|| anyhow!("invalid HTTP response"))?;
    if !(200..300).contains(&status) {
        bail!("JSON-RPC HTTP status {status}");
    }
    serde_json::from_str(http_body(&response)).context("failed to parse JSON-RPC response")
}

fn http_get_status(port: u16, path: &str) -> Result<u16> {
    let response = http_request(port, "GET", path, None)?;
    http_status(&response).ok_or_else(|| anyhow!("invalid HTTP response"))
}

fn http_request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<(&str, &[u8])>,
) -> Result<String> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(1))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    let body_len = body.map(|(_, body)| body.len()).unwrap_or(0);
    let content_type = body.map(|(content_type, _)| content_type);
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Length: {body_len}\r\n"
    );
    if let Some(content_type) = content_type {
        request.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes())?;
    if let Some((_, body)) = body {
        stream.write_all(body)?;
    }

    let mut response = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
                    && !response.is_empty() =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }

    String::from_utf8(response).context("HTTP response was not UTF-8")
}

fn http_status(response: &str) -> Option<u16> {
    response
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn http_body(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}
