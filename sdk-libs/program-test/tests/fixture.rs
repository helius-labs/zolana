use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_program_test::{
    fixture::{
        account_json, actor, payer, payer_token_account, spl_mint, write_test_fixture, ACTOR_COUNT,
        FUNDED_LAMPORTS,
    },
    workspace_path,
};

#[test]
fn account_json_uses_the_solana_dump_format() {
    let pubkey = Pubkey::new_from_array([7u8; 32]);
    let account = Account {
        lamports: 42,
        data: vec![1, 2, 3],
        owner: Pubkey::new_from_array([9u8; 32]),
        executable: false,
        rent_epoch: u64::MAX,
    };
    assert_eq!(
        account_json(&pubkey, &account),
        format!(
            r#"{{"account":{{"data":["AQID","base64"],"executable":false,"lamports":42,"owner":"{}","rentEpoch":18446744073709551615}},"pubkey":"{pubkey}"}}"#,
            account.owner
        )
    );
}

/// Every account the fixture reports is written, the payer and the actors are
/// funded, and the SPL accounts sit at the addresses tests look them up by.
#[test]
fn test_fixture_writes_every_reported_account() {
    let dir = std::env::temp_dir().join(format!("zolana-fixture-test-{}", std::process::id()));
    let accounts = write_test_fixture(
        &workspace_path("target/deploy/shielded_pool_program.so"),
        &dir,
    )
    .expect("write the test fixture");

    let mut written: Vec<String> = std::fs::read_dir(&dir)
        .expect("read the fixture dir")
        .map(|entry| {
            entry
                .expect("fixture entry")
                .file_name()
                .into_string()
                .expect("utf-8 name")
        })
        .collect();
    written.sort();
    let mut expected: Vec<String> = accounts
        .iter()
        .map(|(_, pubkey)| format!("{pubkey}.json"))
        .collect();
    expected.sort();
    assert_eq!(written, expected);

    let funded =
        std::iter::once(payer().pubkey()).chain((0..ACTOR_COUNT).map(|i| actor(i).pubkey()));
    for pubkey in funded {
        let json = std::fs::read_to_string(dir.join(format!("{pubkey}.json"))).expect("read");
        assert!(
            json.contains(&format!(r#""lamports":{FUNDED_LAMPORTS}"#)),
            "{json}"
        );
    }
    let find = |label: &str| {
        accounts
            .iter()
            .find(|(written_label, _)| *written_label == label)
            .map(|(_, pubkey)| *pubkey)
    };
    assert_eq!(find("spl_mint"), Some(spl_mint()));
    assert_eq!(find("payer_token_account"), Some(payer_token_account()));
}
