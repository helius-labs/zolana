use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc,
    thread,
};

use serde_json::{json, Value};
use zolana_api::{ApiError, Base64String, BlockingZolanaApi, Hash, SerializablePubkey, PAGE_LIMIT};

const JSON_CONTENT_TYPE: &str = "application/json";
const SIGNATURE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const TREE_ADDRESS: &str = "treeYbr45LjxovKvtD46uEphM64kwoFFPYhVNw1A8x8";

fn main() {
    match vectors() {
        Ok(value) => println!(
            "{}",
            serde_json::to_string(&value).expect("serialize vectors")
        ),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn vectors() -> Result<Value, Box<dyn std::error::Error>> {
    let tag = Hash::from([1; 32]);
    let leaf = Hash::from([2; 32]);
    let root = Hash::from([3; 32]);
    let low = Hash::from([4; 32]);
    let high = Hash::from([5; 32]);
    let tree = SerializablePubkey::try_from(TREE_ADDRESS)?;
    let cursor = Base64String(vec![7, 8]);

    let encrypted_result = json!({
        "context":{"block_time":101},
        "matches":[{
            "slot":102,
            "tx_signature":SIGNATURE,
            "output_slot":{
                "view_tag":tag.to_string(),
                "output_context":{"hash":leaf.to_string(),"tree":tree.to_string(),"leaf_index":103},
                "payload":"AQID"
            },
            "tx_viewing_pk":"BAU=",
            "salt":"Bgc="
        }],
        "next_cursor":"CAk="
    });
    let transactions_result = json!({
        "context":{"block_time":201},
        "transactions":[{
            "slot":202,
            "tx_signature":SIGNATURE,
            "tx_viewing_pk":"Cgs=",
            "salt":"DA0=",
            "output_slots":[{
                "view_tag":tag.to_string(),
                "output_context":{"hash":leaf.to_string(),"tree":tree.to_string(),"leaf_index":203},
                "payload":"Dg8="
            }],
            "messages":[{"view_tag":root.to_string(),"payload":"EBE="}],
            "nullifiers":[low.to_string()],
            "proofless":false
        }],
        "next_cursor":"EhM="
    });
    let merkle_result = json!({
        "context":{"block_time":301},
        "proofs":[{
            "leaf":leaf.to_string(),
            "merkle_context":{"tree_type":1,"tree":tree.to_string()},
            "path":[low.to_string(),high.to_string()],
            "leaf_index":302,
            "root":root.to_string(),
            "root_seq":303,
            "root_index":304
        }]
    });
    let non_inclusion_result = json!({
        "context":{"block_time":401},
        "proofs":[{
            "leaf":leaf.to_string(),
            "merkle_context":{"tree_type":2,"tree":tree.to_string()},
            "path":[root.to_string(),high.to_string()],
            "low_element":low.to_string(),
            "low_element_index":402,
            "high_element":high.to_string(),
            "high_element_index":403,
            "root":root.to_string(),
            "root_seq":404,
            "root_index":405
        }]
    });
    let queue_default_result = json!({
        "context":{"block_time":501},
        "elements":[{"seq":0,"value":low.to_string()}]
    });
    let queue_explicit_result = json!({
        "context":{"block_time":502},
        "elements":[{"seq":7,"value":high.to_string()}]
    });

    let mut successes = Vec::new();
    successes.push(success_case("encrypted-utxos", encrypted_result, |api| {
        Ok(serde_json::to_value(api.get_encrypted_utxos_by_tags(
            vec![tag.clone()],
            Some(cursor.clone()),
            Some(PAGE_LIMIT),
        )?)
        .expect("serialize encrypted UTXO response"))
    })?);
    successes.push(success_case(
        "shielded-transactions",
        transactions_result,
        |api| {
            Ok(serde_json::to_value(api.get_shielded_transactions_by_tags(
                vec![tag.clone()],
                None,
                None,
            )?)
            .expect("serialize shielded transaction response"))
        },
    )?);
    successes.push(success_case("merkle-proofs", merkle_result, |api| {
        Ok(
            serde_json::to_value(api.get_merkle_proofs(tree, vec![leaf.clone()])?)
                .expect("serialize Merkle proof response"),
        )
    })?);
    successes.push(success_case(
        "non-inclusion-proofs",
        non_inclusion_result,
        |api| {
            Ok(
                serde_json::to_value(api.get_non_inclusion_proofs(tree, vec![leaf.clone()])?)
                    .expect("serialize non-inclusion proof response"),
            )
        },
    )?);
    successes.push(success_case(
        "nullifier-queue-default",
        queue_default_result,
        |api| {
            Ok(
                serde_json::to_value(api.get_nullifier_queue_elements(tree, None, 1)?)
                    .expect("serialize default nullifier queue response"),
            )
        },
    )?);
    successes.push(success_case(
        "nullifier-queue-explicit",
        queue_explicit_result,
        |api| {
            Ok(
                serde_json::to_value(api.get_nullifier_queue_elements(tree, Some(7), 2)?)
                    .expect("serialize explicit nullifier queue response"),
            )
        },
    )?);

    let invalid_optional_limit = BlockingZolanaApi::new("http://127.0.0.1:1")
        .get_encrypted_utxos_by_tags(vec![tag.clone()], None, Some(0))
        .expect_err("zero optional limit");
    let invalid_required_limit = BlockingZolanaApi::new("http://127.0.0.1:1")
        .get_nullifier_queue_elements(tree, None, PAGE_LIMIT + 1)
        .expect_err("oversized required limit");

    let (http_request, http_error) = error_case(
        "503 Service Unavailable",
        "text/plain",
        "fixture unavailable",
        |api| api.get_merkle_proofs(tree, vec![leaf.clone()]).map(|_| ()),
    )?;
    let (json_rpc_request, json_rpc_error) = error_case(
        "200 OK",
        JSON_CONTENT_TYPE,
        r#"{"id":"test-account","jsonrpc":"2.0","error":{"code":-32001,"message":"fixture rejected"}}"#,
        |api| {
            api.get_non_inclusion_proofs(tree, vec![leaf.clone()])
                .map(|_| ())
        },
    )?;
    let (missing_result_request, missing_result_error) = error_case(
        "200 OK",
        JSON_CONTENT_TYPE,
        r#"{"id":"test-account","jsonrpc":"2.0"}"#,
        |api| {
            api.get_nullifier_queue_elements(tree, Some(7), 2)
                .map(|_| ())
        },
    )?;

    Ok(json!({
        "inputs":{
            "cursor":cursor,
            "explicitStartSeq":"7",
            "leaf":leaf,
            "optionalLimit":PAGE_LIMIT.to_string(),
            "queueLimit":"1",
            "queueExplicitLimit":"2",
            "tag":tag,
            "treeAccount":tree.to_string()
        },
        "expected":{
            "successes":successes,
            "errors":{
                "http":{"request":http_request,"error":api_error(&http_error)},
                "invalidOptionalLimit":api_error(&invalid_optional_limit),
                "invalidRequiredLimit":api_error(&invalid_required_limit),
                "jsonRpc":{"request":json_rpc_request,"error":api_error(&json_rpc_error)},
                "missingResult":{
                    "request":missing_result_request,
                    "error":api_error(&missing_result_error)
                }
            }
        }
    }))
}

fn success_case<F>(
    case: &str,
    result: Value,
    invoke: F,
) -> Result<Value, Box<dyn std::error::Error>>
where
    F: FnOnce(&BlockingZolanaApi) -> Result<Value, ApiError>,
{
    let response = json!({"id":"test-account","jsonrpc":"2.0","result":result});
    let (request, decoded) = exchange(
        "200 OK",
        JSON_CONTENT_TYPE,
        &serde_json::to_string(&response)?,
        invoke,
    )?;
    let decoded = decoded.map_err(|error| format!("{case}: {error}"))?;
    Ok(json!({
        "case":case,
        "request":request,
        "response":stringify_numbers(decoded)
    }))
}

fn error_case<T, F>(
    status: &str,
    content_type: &str,
    body: &str,
    invoke: F,
) -> Result<(Value, ApiError), Box<dyn std::error::Error>>
where
    F: FnOnce(&BlockingZolanaApi) -> Result<T, ApiError>,
{
    let (request, result) = exchange(status, content_type, body, invoke)?;
    match result {
        Ok(_) => Err("fixture error response was accepted".into()),
        Err(error) => Ok((request, error)),
    }
}

fn exchange<T, F>(
    status: &str,
    content_type: &str,
    response_body: &str,
    invoke: F,
) -> Result<(Value, Result<T, ApiError>), Box<dyn std::error::Error>>
where
    F: FnOnce(&BlockingZolanaApi) -> Result<T, ApiError>,
{
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let status = status.to_string();
    let content_type = content_type.to_string();
    let response_body = response_body.as_bytes().to_vec();
    let (sender, receiver) = mpsc::channel();
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        let request = read_request(&mut stream).map_err(|error| error.to_string())?;
        sender.send(request).map_err(|error| error.to_string())?;
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        )
        .map_err(|error| error.to_string())?;
        stream
            .write_all(&response_body)
            .map_err(|error| error.to_string())
    });
    let api = BlockingZolanaApi::new(format!("http://{address}/base"));
    let result = invoke(&api);
    let request = receiver.recv()?;
    server.join().map_err(|_| "API fixture server panicked")??;
    Ok((request, result))
}

fn read_request(stream: &mut impl Read) -> Result<Value, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Err("request ended before its headers".into());
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec())?;
    let mut lines = headers.lines();
    let request_line = lines.next().ok_or("missing request line")?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().ok_or("missing HTTP method")?;
    let target = request_parts.next().ok_or("missing HTTP target")?;
    let mut content_length = None;
    let mut content_type = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(value.trim().parse::<usize>()?);
        } else if name.eq_ignore_ascii_case("content-type") {
            content_type = Some(value.trim().to_ascii_lowercase());
        }
    }
    let content_length = content_length.ok_or("missing content-length")?;
    while bytes.len() < header_end + content_length {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Err("request ended before its body".into());
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let body: Value = serde_json::from_slice(&bytes[header_end..header_end + content_length])?;
    Ok(json!({
        "body":body,
        "contentType":content_type.ok_or("missing content-type")?,
        "method":method,
        "path":path,
        "query":query
    }))
}

fn api_error(error: &ApiError) -> Value {
    match error {
        ApiError::Request(_) => json!({"kind":"Request"}),
        ApiError::Response { status, body } => {
            json!({"kind":"Response","status":status.as_u16(),"body":body})
        }
        ApiError::JsonRpc {
            method,
            code,
            message,
        } => json!({"kind":"JsonRpc","method":method,"code":code,"message":message}),
        ApiError::InvalidRequest { field, message } => {
            json!({"kind":"InvalidRequest","field":field,"message":message})
        }
        ApiError::MissingResult(method) => json!({"kind":"MissingResult","method":method}),
    }
}

fn stringify_numbers(value: Value) -> Value {
    stringify_number_fields(value, "")
}

fn stringify_number_fields(value: Value, field: &str) -> Value {
    match value {
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| stringify_number_fields(value, field))
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    let value = stringify_number_fields(value, &key);
                    (key, value)
                })
                .collect(),
        ),
        Value::Number(value)
            if matches!(
                field,
                "block_time"
                    | "high_element_index"
                    | "leaf_index"
                    | "low_element_index"
                    | "root_seq"
                    | "seq"
                    | "slot"
            ) =>
        {
            Value::String(value.to_string())
        }
        value => value,
    }
}
