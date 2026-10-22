use super::*;

#[test]
fn a_request_body_takes_exactly_its_length() {
    let inputs = serde_json::json!({ "nullifierSecret": format!("0x{}", "ab".repeat(32)) });
    let request = RingRequest::new(RingCircuit::RegisterKey, &inputs).unwrap();
    let body = request.body().unwrap();
    assert_eq!(body.capacity(), body.len());
    let sent: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(sent["nullifierSecret"], inputs["nullifierSecret"]);
    assert!(sent["circuitType"].is_string());
}
