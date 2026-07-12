use photon_indexer::openapi::update_docs;

#[test]
pub fn test_documentation_generation() -> anyhow::Result<()> {
    update_docs(true)?;

    let tmp_directory = std::env::temp_dir().join("photon-openapi");
    let rings_spec = std::fs::read_to_string(tmp_directory.join("rings.test.yaml"))?;

    assert!(rings_spec.contains("/get_encrypted_utxos_by_tags"));
    assert!(rings_spec.contains("/get_shielded_transactions_by_tags"));
    assert!(rings_spec.contains("/get_merkle_proofs"));
    assert!(rings_spec.contains("/get_non_inclusion_proofs"));
    Ok(())
}
