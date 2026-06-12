use std::collections::HashMap;
use std::path::PathBuf;

use cucumber::{given, then, when, World};
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_interface::user_registry::user_record_pda;

use light_program_test::user_registry_sdk::{
    build_close_ix, build_register_ix, build_revoke_ix, build_set_sync_delegate_ix,
    build_rotate_sync_delegate_ix, fetch_user_record, user_registry_program_id,
};

#[derive(Default, World)]
pub struct UserRegistryWorld {
    pub svm: Option<LiteSVM>,
    pub payer: Option<Keypair>,
    pub owners: HashMap<String, Keypair>,
    pub sync_delegates: HashMap<String, Keypair>,
    pub strangers: HashMap<String, Keypair>,
    pub owner_p256: HashMap<String, [u8; 33]>,
    pub nullifier_pubkey: HashMap<String, [u8; 32]>,
    pub viewing_pubkey: HashMap<String, [u8; 33]>,
    pub balances: HashMap<String, u64>,
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
        // Advance the blockhash so otherwise-identical transactions (e.g.
        // re-register after close, re-appoint after revoke) get distinct
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
            .or_else(|| self.sync_delegates.get(name))
            .or_else(|| self.strangers.get(name))
            .unwrap_or_else(|| panic!("no keypair named {name}"))
            .insecure_clone()
    }

    fn lamports_of(&self, pubkey: &Pubkey) -> u64 {
        self.svm
            .as_ref()
            .expect("rig")
            .get_account(pubkey)
            .map(|account| account.lamports)
            .unwrap_or(0)
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

fn p256_pubkey_with_prefix(prefix: u8) -> [u8; 33] {
    let mut pubkey = [0u8; 33];
    pubkey[0] = prefix;
    pubkey[1] = 0x77;
    pubkey
}

/// Adversarial builder: targets an arbitrary record PDA with an arbitrary
/// "owner" account, instead of deriving the PDA from the signer like the SDK.
fn raw_set_sync_delegate_ix(
    user_record: Pubkey,
    owner: Pubkey,
    sync_delegate: Pubkey,
) -> solana_instruction::Instruction {
    zolana_interface::user_registry::instruction::set_sync_delegate(
        user_record,
        owner,
        zolana_interface::user_registry::instruction::SetSyncDelegateData {
            sync_delegate: sync_delegate.to_bytes(),
            sync_pubkey: test_p256_pubkey(0xEE),
            viewing_pubkey: test_p256_pubkey(0xEF),
        },
    )
}

fn raw_close_ix(user_record: Pubkey, owner: Pubkey) -> solana_instruction::Instruction {
    zolana_interface::user_registry::instruction::close(user_record, owner)
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

#[when(regex = r#""(.*)" tries to register again"#)]
fn when_register_again(world: &mut UserRegistryWorld, name: String) {
    when_register(world, name);
}

#[when(regex = r#""(.*)" tries to register with viewing key prefix (\d+)"#)]
fn when_register_bad_viewing(world: &mut UserRegistryWorld, name: String, prefix: u8) {
    let owner = world.owners.get(&name).expect("owner").pubkey();
    let ix = build_register_ix(
        &owner,
        Some(world.owner_p256[&name]),
        world.nullifier_pubkey[&name],
        p256_pubkey_with_prefix(prefix),
    );
    let owner_kp = world.owners.get(&name).expect("owner").insecure_clone();
    world.send(&[owner_kp], ix);
}

#[when(regex = r#""(.*)" tries to register with owner p256 prefix (\d+)"#)]
fn when_register_bad_owner_p256(world: &mut UserRegistryWorld, name: String, prefix: u8) {
    let owner = world.owners.get(&name).expect("owner").pubkey();
    let ix = build_register_ix(
        &owner,
        Some(p256_pubkey_with_prefix(prefix)),
        world.nullifier_pubkey[&name],
        world.viewing_pubkey[&name],
    );
    let owner_kp = world.owners.get(&name).expect("owner").insecure_clone();
    world.send(&[owner_kp], ix);
}

#[when(regex = r#""(.*)" tries to register with a non-canonical nullifier pubkey"#)]
fn when_register_bad_nullifier(world: &mut UserRegistryWorld, name: String) {
    let owner = world.owners.get(&name).expect("owner").pubkey();
    let ix = build_register_ix(
        &owner,
        Some(world.owner_p256[&name]),
        zolana_user_registry::constants::BN254_FR_MODULUS,
        world.viewing_pubkey[&name],
    );
    let owner_kp = world.owners.get(&name).expect("owner").insecure_clone();
    world.send(&[owner_kp], ix);
}

// === set_sync_delegate ===

#[given(regex = r#"owner "(.*)" appoints sync delegate "(.*)""#)]
#[when(regex = r#"owner "(.*)" appoints sync delegate "(.*)""#)]
fn when_set_sync_delegate(
    world: &mut UserRegistryWorld,
    owner_name: String,
    sync_delegate_name: String,
) {
    world
        .sync_delegates
        .entry(sync_delegate_name.clone())
        .or_insert_with(Keypair::new);
    let sync_delegate_pubkey = world
        .sync_delegates
        .get(&sync_delegate_name)
        .expect("sync delegate")
        .pubkey();
    world.fund(&sync_delegate_pubkey, 5_000_000_000);
    let owner = world.owners.get(&owner_name).expect("owner").pubkey();
    let sync_pubkey = test_p256_pubkey(sync_delegate_name.len() as u8);
    let viewing_pubkey = test_p256_pubkey(0xB0 + sync_delegate_name.len() as u8);
    let ix = build_set_sync_delegate_ix(&owner, sync_delegate_pubkey, sync_pubkey, viewing_pubkey);
    let owner_kp = world
        .owners
        .get(&owner_name)
        .expect("owner")
        .insecure_clone();
    world.send(&[owner_kp], ix);
}

#[when(regex = r#"owner "(.*)" tries to appoint sync delegate "(.*)" with sync key prefix (\d+)"#)]
fn when_set_sync_delegate_bad_key(
    world: &mut UserRegistryWorld,
    owner_name: String,
    sync_delegate_name: String,
    prefix: u8,
) {
    world
        .sync_delegates
        .entry(sync_delegate_name.clone())
        .or_insert_with(Keypair::new);
    let sync_delegate_pubkey = world
        .sync_delegates
        .get(&sync_delegate_name)
        .expect("sync delegate")
        .pubkey();
    let owner = world.owners.get(&owner_name).expect("owner").pubkey();
    let ix = build_set_sync_delegate_ix(
        &owner,
        sync_delegate_pubkey,
        p256_pubkey_with_prefix(prefix),
        test_p256_pubkey(0xB1),
    );
    let owner_kp = world
        .owners
        .get(&owner_name)
        .expect("owner")
        .insecure_clone();
    world.send(&[owner_kp], ix);
}

#[when(regex = r#"stranger "(.*)" tries to appoint (?:himself|herself) as sync delegate for "(.*)""#)]
fn when_stranger_set_sync_delegate(
    world: &mut UserRegistryWorld,
    stranger_name: String,
    owner_name: String,
) {
    let owner = world.owners.get(&owner_name).expect("owner").pubkey();
    let (victim_record, _bump) = user_record_pda(&owner);
    let stranger = world
        .strangers
        .get(&stranger_name)
        .expect("stranger")
        .insecure_clone();
    let ix = raw_set_sync_delegate_ix(victim_record, stranger.pubkey(), stranger.pubkey());
    world.send(&[stranger], ix);
}

// === rotate_sync_delegate ===

#[given(regex = r#"sync delegate "(.*)" rotates keys for "(.*)""#)]
#[when(regex = r#"sync delegate "(.*)" rotates keys for "(.*)""#)]
fn when_rotate_sync_delegate(
    world: &mut UserRegistryWorld,
    sync_delegate_name: String,
    owner_name: String,
) {
    let owner = world.owners.get(&owner_name).expect("owner").pubkey();
    let sync_delegate_kp = world
        .sync_delegates
        .get(&sync_delegate_name)
        .expect("sync delegate")
        .insecure_clone();
    let sync_pubkey = test_p256_pubkey(0xC0 + sync_delegate_name.len() as u8);
    let viewing_pubkey = test_p256_pubkey(0xD0 + sync_delegate_name.len() as u8);
    let ix = build_rotate_sync_delegate_ix(
        &owner,
        &sync_delegate_kp.pubkey(),
        sync_pubkey,
        viewing_pubkey,
    );
    world.send(&[sync_delegate_kp], ix);
}

#[when(regex = r#""(.*)" tries to rotate sync delegate keys for "(.*)""#)]
fn when_rotate_attempt(world: &mut UserRegistryWorld, signer_name: String, owner_name: String) {
    let owner = world.owners.get(&owner_name).expect("owner").pubkey();
    let signer = world.keypair_named(&signer_name);
    let ix = build_rotate_sync_delegate_ix(
        &owner,
        &signer.pubkey(),
        test_p256_pubkey(0xE0),
        test_p256_pubkey(0xE1),
    );
    world.send(&[signer], ix);
}

#[when(regex = r#"sync delegate "(.*)" tries to rotate keys for "(.*)" with viewing key prefix (\d+)"#)]
fn when_rotate_bad_key(
    world: &mut UserRegistryWorld,
    sync_delegate_name: String,
    owner_name: String,
    prefix: u8,
) {
    let owner = world.owners.get(&owner_name).expect("owner").pubkey();
    let sync_delegate_kp = world
        .sync_delegates
        .get(&sync_delegate_name)
        .expect("sync delegate")
        .insecure_clone();
    let ix = build_rotate_sync_delegate_ix(
        &owner,
        &sync_delegate_kp.pubkey(),
        test_p256_pubkey(0xE2),
        p256_pubkey_with_prefix(prefix),
    );
    world.send(&[sync_delegate_kp], ix);
}

// === revoke ===

#[given(regex = r#""(.*)" revokes sync delegate for "(.*)""#)]
#[when(regex = r#""(.*)" revokes sync delegate for "(.*)""#)]
fn when_revoke(world: &mut UserRegistryWorld, signer_name: String, owner_name: String) {
    let owner = world.owners.get(&owner_name).expect("owner").pubkey();
    let signer_kp = world.keypair_named(&signer_name);
    let ix = build_revoke_ix(&owner, &signer_kp.pubkey());
    world.send(&[signer_kp], ix);
}

// === close ===

#[when(regex = r#""(.*)" closes the record"#)]
fn when_close(world: &mut UserRegistryWorld, name: String) {
    let owner = world.owners.get(&name).expect("owner").pubkey();
    world
        .balances
        .insert(name.clone(), world.lamports_of(&owner));
    let ix = build_close_ix(&owner);
    let owner_kp = world.owners.get(&name).expect("owner").insecure_clone();
    world.send(&[owner_kp], ix);
}

#[when(regex = r#"^"(.*)" tries to close the record$"#)]
fn when_close_fails(world: &mut UserRegistryWorld, name: String) {
    when_close(world, name);
}

#[when(regex = r#"stranger "(.*)" tries to close the record of "(.*)""#)]
fn when_stranger_close(
    world: &mut UserRegistryWorld,
    stranger_name: String,
    owner_name: String,
) {
    let owner = world.owners.get(&owner_name).expect("owner").pubkey();
    let (victim_record, _bump) = user_record_pda(&owner);
    let stranger = world
        .strangers
        .get(&stranger_name)
        .expect("stranger")
        .insecure_clone();
    let ix = raw_close_ix(victim_record, stranger.pubkey());
    world.send(&[stranger], ix);
}

// === then ===

fn assert_no_error(world: &UserRegistryWorld) {
    assert!(
        world.last_error.is_none(),
        "tx failed: {:?}",
        world.last_error
    );
}

#[then(regex = r#""(.*)" has a user record with no sync delegate"#)]
fn then_no_sync_delegate(world: &mut UserRegistryWorld, name: String) {
    assert_no_error(world);
    let owner = world.owners.get(&name).expect("owner").pubkey();
    let record =
        fetch_user_record(world.svm.as_ref().expect("rig"), &owner).expect("record missing");
    assert_eq!(record.owner, owner.to_bytes());
    assert_eq!(record.bump, user_record_pda(&owner).1, "stored bump must be canonical");
    assert!(record.sync_delegate.is_none());
    assert!(record.entries.is_empty());
    assert_eq!(record.nullifier_pubkey, world.nullifier_pubkey[&name]);
    assert_eq!(record.viewing_pubkey, world.viewing_pubkey[&name]);
    assert_eq!(record.sender_viewing_pubkey(), record.viewing_pubkey);
}

#[then(regex = r#""(.*)" has a user record without an owner p256 key"#)]
fn then_record_no_p256(world: &mut UserRegistryWorld, name: String) {
    assert_no_error(world);
    let owner = world.owners.get(&name).expect("owner").pubkey();
    let record =
        fetch_user_record(world.svm.as_ref().expect("rig"), &owner).expect("record missing");
    assert!(record.owner_p256.is_none());
    assert_eq!(record.nullifier_pubkey, world.nullifier_pubkey[&name]);
    assert_eq!(record.viewing_pubkey, world.viewing_pubkey[&name]);
}

#[then(regex = r#""(.*)" has sync delegate "(.*)" with (\d+) entries"#)]
fn then_sync_delegate_entries(
    world: &mut UserRegistryWorld,
    owner_name: String,
    sync_delegate_name: String,
    count: usize,
) {
    assert_no_error(world);
    let owner = world.owners.get(&owner_name).expect("owner").pubkey();
    let record =
        fetch_user_record(world.svm.as_ref().expect("rig"), &owner).expect("record missing");
    assert_eq!(record.bump, user_record_pda(&owner).1, "stored bump must survive updates");
    assert_eq!(
        record.sync_delegate,
        Some(
            world
                .sync_delegates
                .get(&sync_delegate_name)
                .expect("sync delegate")
                .pubkey()
                .to_bytes()
        )
    );
    assert_eq!(record.entries.len(), count);
    // Active delegate: senders must see the latest entry's viewing key,
    // not the static one.
    assert_eq!(
        record.sender_viewing_pubkey(),
        record.entries.last().expect("entry").viewing_pubkey
    );
}

#[then(regex = r#""(.*)" has no sync delegate and (\d+) entries"#)]
fn then_revoked(world: &mut UserRegistryWorld, owner_name: String, count: usize) {
    assert_no_error(world);
    let owner = world.owners.get(&owner_name).expect("owner").pubkey();
    let record =
        fetch_user_record(world.svm.as_ref().expect("rig"), &owner).expect("record missing");
    assert!(record.sync_delegate.is_none());
    assert_eq!(record.entries.len(), count);
    assert_eq!(record.sender_viewing_pubkey(), record.viewing_pubkey);
}

#[then(regex = r#""(.*)" has no user record"#)]
fn then_no_record(world: &mut UserRegistryWorld, name: String) {
    assert_no_error(world);
    let owner = world.owners.get(&name).expect("owner").pubkey();
    let (pda, _) = user_record_pda(&owner);
    assert!(world.svm.as_ref().expect("rig").get_account(&pda).is_none());
}

#[then(regex = r#""(.*)" received the rent refund"#)]
fn then_rent_refunded(world: &mut UserRegistryWorld, name: String) {
    let owner = world.owners.get(&name).expect("owner").pubkey();
    let before = *world.balances.get(&name).expect("pre-close balance");
    let after = world.lamports_of(&owner);
    assert!(
        after > before,
        "owner balance must grow by the reclaimed rent: before={before} after={after}"
    );
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
