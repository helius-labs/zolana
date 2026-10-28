use super::*;
use feature_gate::CircuitFeature;

#[test]
fn reports_the_binary_feature_state_without_using_this_clis_compile_features() {
    const DISABLED: CircuitFeature = CircuitFeature {
        name: "confidential-eddsa",
        enabled: false,
        proving_key_sha256s: &[[7; 32]],
    };
    const ENABLED: CircuitFeature = CircuitFeature {
        enabled: true,
        ..DISABLED
    };
    let disabled = DISABLED.encode::<{ DISABLED.encoded_len() }>();
    let enabled = ENABLED.encode::<{ ENABLED.encoded_len() }>();
    assert_eq!(
        report(&disabled).unwrap(),
        format!(
            "confidential-eddsa: disabled\n  proving_key_sha256={}\n",
            "07".repeat(32)
        )
    );
    assert_eq!(
        report(&enabled).unwrap(),
        format!(
            "confidential-eddsa: enabled\n  proving_key_sha256={}\n",
            "07".repeat(32)
        )
    );
    assert!(report(b"\x7fELF no metadata")
        .unwrap_err()
        .to_string()
        .contains("unknown"));
    assert!(report(feature_gate::BEGIN).is_err());
}

#[test]
fn validates_upgradeable_program_data_before_inspection() {
    let mut data = bincode::serialize(&UpgradeableLoaderState::ProgramData {
        slot: 42,
        upgrade_authority_address: None,
    })
    .unwrap();
    data.resize(UpgradeableLoaderState::size_of_programdata_metadata(), 0);
    data.extend_from_slice(b"\x7fELF");
    let mut account = Account {
        data,
        owner: bpf_loader_upgradeable::ID,
        ..Default::default()
    };
    assert_eq!(upgradeable_binary(&account).unwrap(), b"\x7fELF");
    account.owner = solana_sdk_ids::system_program::ID;
    assert!(upgradeable_binary(&account).is_err());
    account.owner = bpf_loader_upgradeable::ID;
    account.data = bincode::serialize(&UpgradeableLoaderState::Program {
        programdata_address: Address::new_unique(),
    })
    .unwrap();
    assert!(upgradeable_binary(&account).is_err());
}

#[test]
fn local_and_deployed_sources_are_unambiguous() {
    assert!(Options::parse(vec!["--so".into(), "program.so".into()])
        .unwrap()
        .so
        .is_some());
    assert!(Options::parse(vec![
        "--so".into(),
        "program.so".into(),
        "--rpc-url".into(),
        "http://localhost:8899".into()
    ])
    .is_err());
    assert!(Options::parse(vec!["--so".into()]).is_err());
}
