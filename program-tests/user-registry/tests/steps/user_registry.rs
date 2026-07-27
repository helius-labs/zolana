use std::{collections::HashMap, path::PathBuf};

use cucumber::{given, then, when, World};
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use user_registry_tests::{
    build_register_ix, build_set_merging_enabled_ix, build_update_keys_ix, fetch_user_record,
    user_registry_program_id,
};
use zolana_user_registry_interface::user_record_pda;

#[derive(Default, World)]
pub struct UserRegistryWorld {
    pub svm: Option<LiteSVM>,
    pub payer: Option<Keypair>,
    pub owners: HashMap<String, Keypair>,
    pub strangers: HashMap<String, Keypair>,
    pub owner_p256: HashMap<String, [u8; 33]>,
    pub nullifier_pubkey: HashMap<String, [u8; 32]>,
    pub viewing_pubkey: HashMap<String, [u8; 33]>,
    pub last_error: Option<String>,
}

impl std::fmt::Debug for UserRegistryWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserRegistryWorld")
    }
}

impl UserRegistryWorld {
    fn send(&mut self, signers: &[Keypair], ix: solana_instruction::Instruction) {
        self.last_error = None;
        let payer = self.payer.as_ref().expect("payer").insecure_clone();
        let mut all = vec![payer];
        all.extend(signers.iter().map(Keypair::insecure_clone));
        let payer_pubkey = all[0].pubkey();
        // Advance the blockhash so otherwise-identical transactions get distinct
        // signatures and are not rejected as AlreadyProcessed.
        self.svm.as_mut().expect("rig").expire_blockhash();
        let blockhash = self.svm.as_mut().expect("rig").latest_blockhash();
        let msg = Message::new(&[ix], Some(&payer_pubkey));
        let signer_refs: Vec<&Keypair> = all.iter().collect();
        let tx = Transaction::new(&signer_refs, msg, blockhash);
        if let Err(err) = self.svm.as_mut().expect("rig").send_transaction(tx) {
            self.last_error = Some(format!("{err:?}"));
        }
    }

    /// Fund an account, advancing the blockhash first so repeat airdrops to
    /// the same key with the same amount don't collide as AlreadyProcessed.
    fn fund(&mut self, pubkey: &Pubkey, lamports: u64) {
        let svm = self.svm.as_mut().expect("rig");
        svm.expire_blockhash();
        svm.airdrop(pubkey, lamports).expect("airdrop");
    }

    /// Look up a named keypair regardless of which role created it.
    fn keypair_named(&self, name: &str) -> Keypair {
        self.owners
            .get(name)
            .or_else(|| self.strangers.get(name))
            .unwrap_or_else(|| panic!("no keypair named {name}"))
            .insecure_clone()
    }
}

fn default_program_path() -> PathBuf {
    if let Ok(p) = std::env::var("USER_REGISTRY_PROGRAM_PATH") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("deploy")
        .join("zolana_user_registry.so")
}

fn test_p256_pubkey(tag: u8) -> [u8; 33] {
    let mut pubkey = [0u8; 33];
    pubkey[0] = 0x02;
    pubkey[1] = tag;
    pubkey
}

// === given ===

#[given("a funded user registry test rig")]
fn given_rig(world: &mut UserRegistryWorld) {
    let path = default_program_path();
    assert!(
        path.exists(),
        "missing {}; run `just build-programs`",
        path.display()
    );
    let mut svm = LiteSVM::new();
    let bytes = std::fs::read(&path).expect("read program");
    svm.add_program(user_registry_program_id(), &bytes)
        .expect("add program");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 20_000_000_000)
        .expect("airdrop payer");
    world.svm = Some(svm);
    world.payer = Some(payer);
}

fn fund_new_keypair(world: &mut UserRegistryWorld, lamports: u64) -> Keypair {
    let kp = Keypair::new();
    world.fund(&kp.pubkey(), lamports);
    kp
}

#[given(regex = r#"owner "(.*)" with p256 keys"#)]
fn given_owner_keys(world: &mut UserRegistryWorld, name: String) {
    let kp = fund_new_keypair(world, 5_000_000_000);
    world.owners.insert(name.clone(), kp);
    world
        .owner_p256
        .insert(name.clone(), test_p256_pubkey(name.len() as u8));
    world.nullifier_pubkey.insert(name.clone(), {
        let mut n = [0u8; 32];
        n[31] = 1;
        n
    });
    world
        .viewing_pubkey
        .insert(name.clone(), test_p256_pubkey(0xA0 + name.len() as u8));
}

#[given(regex = r#"a stranger "(.*)""#)]
fn given_stranger(world: &mut UserRegistryWorld, name: String) {
    let kp = fund_new_keypair(world, 5_000_000_000);
    world.strangers.insert(name, kp);
}

/// Sends lamports to the (not yet created) record PDA so register has to take
/// the transfer + allocate + assign path instead of plain create_account.
#[given(regex = r#"the record address of "(.*)" is pre-funded"#)]
fn given_prefunded_record(world: &mut UserRegistryWorld, name: String) {
    let owner = world.owners.get(&name).expect("owner").pubkey();
    let (pda, _bump) = user_record_pda(&owner);
    world.fund(&pda, 1_000_000);
}

// === register ===

#[given(regex = r#"^"(.*)" registers on-chain$"#)]
#[when(regex = r#"^"(.*)" registers on-chain$"#)]
fn when_register(world: &mut UserRegistryWorld, name: String) {
    let owner = world.owners.get(&name).expect("owner").pubkey();
    let ix = build_register_ix(
        &owner,
        Some(world.owner_p256[&name]),
        world.nullifier_pubkey[&name],
        world.viewing_pubkey[&name],
    );
    let owner_kp = world.owners.get(&name).expect("owner").insecure_clone();
    world.send(&[owner_kp], ix);
}

#[when(regex = r#""(.*)" registers on-chain without an owner p256 key"#)]
fn when_register_no_p256(world: &mut UserRegistryWorld, name: String) {
    let owner = world.owners.get(&name).expect("owner").pubkey();
    let ix = build_register_ix(
        &owner,
        None,
        world.nullifier_pubkey[&name],
        world.viewing_pubkey[&name],
    );
    let owner_kp = world.owners.get(&name).expect("owner").insecure_clone();
    world.send(&[owner_kp], ix);
}

#[when(regex = r#"^"(.*)" updates registry keys$"#)]
fn when_update_keys(world: &mut UserRegistryWorld, name: String) {
    let owner = world.owners.get(&name).expect("owner").pubkey();
    let updated_owner_p256 = test_p256_pubkey(0xF1);
    let mut updated_nullifier = [0u8; 32];
    updated_nullifier[31] = 0xF2;
    let updated_viewing = test_p256_pubkey(0xF3);
    world.owner_p256.insert(name.clone(), updated_owner_p256);
    world
        .nullifier_pubkey
        .insert(name.clone(), updated_nullifier);
    world.viewing_pubkey.insert(name.clone(), updated_viewing);
    let ix = build_update_keys_ix(
        &owner,
        Some(updated_owner_p256),
        updated_nullifier,
        updated_viewing,
    );
    let owner_kp = world.owners.get(&name).expect("owner").insecure_clone();
    world.send(&[owner_kp], ix);
}

#[when(regex = r#"^"(.*)" updates registry keys without an owner p256 key$"#)]
fn when_update_keys_no_p256(world: &mut UserRegistryWorld, name: String) {
    let owner = world.owners.get(&name).expect("owner").pubkey();
    let mut updated_nullifier = [0u8; 32];
    updated_nullifier[31] = 0xF4;
    let updated_viewing = test_p256_pubkey(0xF5);
    world
        .nullifier_pubkey
        .insert(name.clone(), updated_nullifier);
    world.viewing_pubkey.insert(name.clone(), updated_viewing);
    let ix = build_update_keys_ix(&owner, None, updated_nullifier, updated_viewing);
    let owner_kp = world.owners.get(&name).expect("owner").insecure_clone();
    world.send(&[owner_kp], ix);
}

#[when(regex = r#""(.*)" tries to register again"#)]
fn when_register_again(world: &mut UserRegistryWorld, name: String) {
    when_register(world, name);
}

// === set_merging_enabled ===

#[given(regex = r#"owner "(.*)" enables merge service"#)]
#[when(regex = r#"owner "(.*)" enables merge service"#)]
fn when_enable_merge_service(world: &mut UserRegistryWorld, name: String) {
    let owner_kp = world.owners.get(&name).expect("owner").insecure_clone();
    let ix = build_set_merging_enabled_ix(&owner_kp.pubkey(), &owner_kp.pubkey(), true);
    world.send(&[owner_kp], ix);
}

#[when(regex = r#"owner "(.*)" disables merge service"#)]
fn when_disable_merge_service(world: &mut UserRegistryWorld, name: String) {
    let owner_kp = world.owners.get(&name).expect("owner").insecure_clone();
    let ix = build_set_merging_enabled_ix(&owner_kp.pubkey(), &owner_kp.pubkey(), false);
    world.send(&[owner_kp], ix);
}

#[when(regex = r#""(.*)" tries to enable merge service for "(.*)""#)]
fn when_stranger_enable_merge_service(
    world: &mut UserRegistryWorld,
    signer_name: String,
    owner_name: String,
) {
    let owner = world.owners.get(&owner_name).expect("owner").pubkey();
    let signer_kp = world.keypair_named(&signer_name);
    let ix = build_set_merging_enabled_ix(&owner, &signer_kp.pubkey(), true);
    world.send(&[signer_kp], ix);
}

// === then ===

fn assert_no_error(world: &UserRegistryWorld) {
    assert!(
        world.last_error.is_none(),
        "tx failed: {:?}",
        world.last_error
    );
}

#[then(regex = r#""(.*)" has merge service (enabled|disabled)"#)]
fn then_merge_service(world: &mut UserRegistryWorld, name: String, state: String) {
    assert_no_error(world);
    let owner = world.owners.get(&name).expect("owner").pubkey();
    let record =
        fetch_user_record(world.svm.as_ref().expect("rig"), &owner).expect("record missing");
    assert_eq!(record.merging_enabled, state == "enabled");
}

#[then(regex = r#"^"(.*)" has a user record$"#)]
fn then_user_record(world: &mut UserRegistryWorld, name: String) {
    assert_no_error(world);
    let owner = world.owners.get(&name).expect("owner").pubkey();
    let record =
        fetch_user_record(world.svm.as_ref().expect("rig"), &owner).expect("record missing");
    assert_eq!(record.owner.to_bytes(), owner.to_bytes());
    assert_eq!(
        record.bump,
        user_record_pda(&owner).1,
        "stored bump must be canonical"
    );
    assert_eq!(record.nullifier_pubkey, world.nullifier_pubkey[&name]);
    assert_eq!(record.viewing_pubkey, world.viewing_pubkey[&name]);
}

#[then(regex = r#"^"(.*)" has a user record without an owner p256 key$"#)]
fn then_record_no_p256(world: &mut UserRegistryWorld, name: String) {
    assert_no_error(world);
    let owner = world.owners.get(&name).expect("owner").pubkey();
    let record =
        fetch_user_record(world.svm.as_ref().expect("rig"), &owner).expect("record missing");
    assert!(record.owner_p256.is_none());
    assert_eq!(record.nullifier_pubkey, world.nullifier_pubkey[&name]);
    assert_eq!(record.viewing_pubkey, world.viewing_pubkey[&name]);
}

#[then("the transaction fails")]
fn then_fails(world: &mut UserRegistryWorld) {
    assert!(
        world.last_error.is_some(),
        "expected failure but transaction succeeded"
    );
}

#[then(regex = r#"the transaction fails with "(.*)""#)]
fn then_fails_with(world: &mut UserRegistryWorld, needle: String) {
    let err = world
        .last_error
        .as_ref()
        .expect("expected failure but transaction succeeded");
    assert!(
        err.contains(&needle),
        "expected error containing {needle:?}, got: {err}"
    );
}
