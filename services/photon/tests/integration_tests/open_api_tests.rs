use photon_indexer::openapi::update_docs;
use utoipa::openapi::{OpenApi, RefOr, Required};

const METHODS: [&str; 5] = [
    "get_encrypted_utxos_by_tags",
    "get_merkle_proofs",
    "get_non_inclusion_proofs",
    "get_nullifier_queue_elements",
    "get_shielded_transactions_by_tags",
];

#[test]
pub fn test_documentation_generation() -> anyhow::Result<()> {
    update_docs(true)?;

    let tmp_directory = std::env::temp_dir().join("photon-openapi");
    let rings_spec = std::fs::read_to_string(tmp_directory.join("rings.test.yaml"))?;
    let document: OpenApi = serde_norway::from_str(&rings_spec)?;

    let paths = document
        .paths
        .paths
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let expected_paths = METHODS
        .iter()
        .map(|method| format!("/{method}"))
        .collect::<Vec<_>>();
    assert_eq!(paths, expected_paths);

    for method in METHODS {
        let path = format!("/{method}");
        let path_item = document.paths.paths.get(&path).expect("path should exist");
        assert_eq!(path_item.summary.as_deref(), Some(method));
        assert!(path_item.get.is_none());
        assert!(path_item.put.is_none());
        assert!(path_item.delete.is_none());
        assert!(path_item.options.is_none());
        assert!(path_item.head.is_none());
        assert!(path_item.patch.is_none());
        assert!(path_item.trace.is_none());

        let operation = path_item.post.as_ref().expect("method should use POST");
        let request = operation
            .request_body
            .as_ref()
            .expect("method should document its request body");
        assert!(matches!(request.required, Some(Required::True)));
        assert!(request
            .content
            .get("application/json")
            .and_then(|content| content.schema.as_ref())
            .is_some());

        let response_codes = operation
            .responses
            .responses
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(response_codes, ["200", "429", "500"]);
        for response in operation.responses.responses.values() {
            let RefOr::T(response) = response else {
                panic!("method responses should be inline");
            };
            assert!(response
                .content
                .get("application/json")
                .and_then(|content| content.schema.as_ref())
                .is_some());
        }
    }

    assert!(document
        .components
        .as_ref()
        .is_some_and(|components| !components.schemas.is_empty()));
    Ok(())
}
