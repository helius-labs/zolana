//! Rust-generated certification vectors for the K6 through K10 suites of
//! `planning/typescript-sdk-port/proof-and-key-parity.md`. The companion
//! `parity_vectors.rs` covers the values a caller sees; this file covers the
//! derivation layers underneath them and the boundaries that separate a correct
//! implementation from a plausible one.
//!
//! Every value is produced by the current `zolana-keypair` crate through its
//! public API. Regenerate with `UPDATE_KEYPAIR_VECTORS=1 cargo test -p
//! zolana-keypair --test crypto_certification`.
//!
//! # Why keystreams
//!
//! Both ciphers are AES-256-CTR, so encrypting an all-zero plaintext returns the
//! raw keystream. A keystream pins the AES key, the nonce and the initial
//! counter block jointly: change any one of them and every byte differs.
//! `derive_key_nonce` and the merge `key_schedule` are private to the crate and
//! the fixture contract forbids re-deriving them in the generator, so the
//! keystream is the strongest evidence for those three values that production
//! Rust actually exposes. Five blocks are recorded so a counter that increments
//! wrongly across the block boundary shows up too.

use serde_json::{json, Map, Value};
use zolana_keypair::{
    constants::{BLINDING_LEN, PUBLIC_KEY_LEN, SALT_LEN},
    error::KeypairError,
    hash::sha256_be,
    merge::{merge_ciphertext_hash, merge_public_contribution, symmetric_apply, MERGE_INFO},
    nullifier_key::NullifierKey,
    pubkey::{P256Pubkey, PublicKey},
    shielded::ShieldedKeypair,
    signing_key::SigningKey,
    traits::{ShieldedKeypairTrait, ViewingKeyTrait},
    viewing_key::{Salt, ViewTag, ViewingKey},
};

const VECTOR_PATH: &str = "../ts/vectors/keypair-crypto-cert-v1.json";

/// Five AES blocks: enough that a counter which fails to increment, or
/// increments in the wrong byte order, diverges from the second block onwards.
const KEYSTREAM_LEN: usize = 80;

const BASE_SALT: Salt = [0x5a; SALT_LEN];
const BASE_SLOT: u32 = 3;

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Deterministic 32-byte secret material, matching `parity_vectors.rs` so a
/// reader can line the two files up by seed.
fn secret32(seed: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8).wrapping_mul(7) | 1;
    }
    bytes
}

fn viewing(seed: u8) -> ViewingKey {
    ViewingKey::from_bytes(&secret32(seed)).expect("seeded p256 secret is in range")
}

fn zeros(length: usize) -> Vec<u8> {
    vec![0u8; length]
}

fn transfer_keystream(
    sender: &ViewingKey,
    recipient: &P256Pubkey,
    salt: Salt,
    slot: u32,
) -> Vec<u8> {
    sender
        .encrypt_slot(recipient, &zeros(KEYSTREAM_LEN), salt, slot)
        .expect("transfer keystream")
}

/// One row of the derivation-boundary matrix: every input of the transfer key
/// schedule perturbed on its own, so a TypeScript implementation that drops one
/// of them from the derivation fails on exactly that row.
fn boundary_case(
    name: &str,
    sender: &ViewingKey,
    recipient: &P256Pubkey,
    salt: Salt,
    slot: u32,
) -> Value {
    json!({
        "case": name,
        "senderPublicKeyBytes": hex(sender.pubkey().as_bytes()),
        "recipientPublicKeyBytes": hex(recipient.as_bytes()),
        "saltBytes": hex(&salt),
        "slot": slot,
        "keystreamBytes": hex(&transfer_keystream(sender, recipient, salt, slot)),
    })
}

fn transfer_encryption() -> Value {
    let sender = viewing(11);
    let recipient = viewing(23);
    let stranger = viewing(37);

    let mut flipped_salt = BASE_SALT;
    flipped_salt[SALT_LEN - 1] ^= 0x01;

    let boundaries = vec![
        boundary_case("base", &sender, &recipient.pubkey(), BASE_SALT, BASE_SLOT),
        boundary_case(
            "slot",
            &sender,
            &recipient.pubkey(),
            BASE_SALT,
            BASE_SLOT + 1,
        ),
        boundary_case(
            "salt",
            &sender,
            &recipient.pubkey(),
            flipped_salt,
            BASE_SLOT,
        ),
        boundary_case(
            "recipient",
            &sender,
            &stranger.pubkey(),
            BASE_SALT,
            BASE_SLOT,
        ),
        boundary_case(
            "ephemeral",
            &stranger,
            &recipient.pubkey(),
            BASE_SALT,
            BASE_SLOT,
        ),
    ];

    // One bit per byte position of the big-endian slot encoding. A
    // little-endian slot would map 1 to the keystream recorded for 16777216.
    let slot_encoding: Vec<Value> = [1u32, 256, 65_536, 16_777_216, u32::MAX]
        .into_iter()
        .map(|slot| {
            json!({
                "slot": slot,
                "keystreamBytes": hex(&transfer_keystream(&sender, &recipient.pubkey(), BASE_SALT, slot)),
            })
        })
        .collect();

    // The salt enters the HKDF info verbatim, so a reversed copy must not
    // produce the first row's keystream.
    let salt_positions: Vec<Value> = [
        {
            let mut salt = [0u8; SALT_LEN];
            salt[0] = 1;
            salt
        },
        {
            let mut salt = [0u8; SALT_LEN];
            salt[SALT_LEN - 1] = 1;
            salt
        },
    ]
    .into_iter()
    .map(|salt| {
        json!({
            "saltBytes": hex(&salt),
            "keystreamBytes": hex(&transfer_keystream(&sender, &recipient.pubkey(), salt, BASE_SLOT)),
        })
    })
    .collect();

    let plaintext = b"cert/transfer utxo bundle".to_vec();
    let ciphertext = sender
        .encrypt_slot(&recipient.pubkey(), &plaintext, BASE_SALT, BASE_SLOT)
        .expect("transfer ciphertext");

    // The production flow encrypts under a per-transaction viewing key derived
    // from the first nullifier, not under the long-term viewing key.
    let first_nullifier = sha256_be(b"cert/first nullifier");
    let tx_viewing = sender
        .get_transaction_viewing_key(&first_nullifier)
        .expect("transaction viewing key");
    let tx_ciphertext = tx_viewing
        .encrypt_slot(&recipient.pubkey(), &plaintext, BASE_SALT, BASE_SLOT)
        .expect("transaction-keyed ciphertext");

    json!({
        "keystreamLength": KEYSTREAM_LEN,
        "senderSecretBytes": hex(&secret32(11)),
        "recipientSecretBytes": hex(&secret32(23)),
        "strangerSecretBytes": hex(&secret32(37)),
        "senderPublicKeyBytes": hex(sender.pubkey().as_bytes()),
        "recipientPublicKeyBytes": hex(recipient.pubkey().as_bytes()),
        "strangerPublicKeyBytes": hex(stranger.pubkey().as_bytes()),
        "baseSaltBytes": hex(&BASE_SALT),
        "baseSlot": BASE_SLOT,
        "flippedSaltBytes": hex(&flipped_salt),
        "ecdhBytes": hex(&sender.ecdh(&recipient.pubkey()).expect("ecdh")),
        "ecdhReverseBytes": hex(&recipient.ecdh(&sender.pubkey()).expect("reverse ecdh")),
        "boundaries": boundaries,
        "slotEncoding": slot_encoding,
        "saltPositions": salt_positions,
        "plaintextBytes": hex(&plaintext),
        "ciphertextBytes": hex(&ciphertext),
        "recoveredBytes": hex(
            &recipient
                .decrypt_utxo(&ciphertext, &sender.pubkey(), BASE_SALT, BASE_SLOT)
                .expect("recipient decrypt"),
        ),
        "ephemeralRecoveredBytes": hex(
            &sender
                .decrypt_slot_ephemeral(&recipient.pubkey(), &ciphertext, BASE_SALT, BASE_SLOT)
                .expect("ephemeral decrypt"),
        ),
        // CTR has no authentication tag, so every wrong-input decryption
        // returns plaintext-length garbage rather than an error. The exact
        // garbage is recorded: a port that derives a different wrong key would
        // otherwise pass a mere "not equal to the plaintext" assertion.
        "wrongRecipientRecoveredBytes": hex(
            &stranger
                .decrypt_utxo(&ciphertext, &sender.pubkey(), BASE_SALT, BASE_SLOT)
                .expect("stranger decrypt"),
        ),
        "wrongEphemeralRecoveredBytes": hex(
            &recipient
                .decrypt_utxo(&ciphertext, &stranger.pubkey(), BASE_SALT, BASE_SLOT)
                .expect("wrong ephemeral decrypt"),
        ),
        "transactionViewingKey": {
            "firstNullifierBytes": hex(&first_nullifier),
            "publicKeyBytes": hex(tx_viewing.pubkey().as_bytes()),
            "ciphertextBytes": hex(&tx_ciphertext),
            "recoveredBytes": hex(
                &recipient
                    .decrypt_utxo(&tx_ciphertext, &tx_viewing.pubkey(), BASE_SALT, BASE_SLOT)
                    .expect("transaction-keyed decrypt"),
            ),
        },
    })
}

/// Two viewing keys whose compressed public keys carry different SEC1 prefixes,
/// so `pack33` is certified on both parity branches rather than on whichever one
/// the first seed happened to produce.
fn keys_by_prefix() -> (ViewingKey, ViewingKey) {
    let mut even = None;
    let mut odd = None;
    for seed in 1u8..=255 {
        let Ok(key) = ViewingKey::from_bytes(&secret32(seed)) else {
            continue;
        };
        let slot = if key.pubkey().y_is_odd() {
            &mut odd
        } else {
            &mut even
        };
        slot.get_or_insert(seed);
        if even.is_some() && odd.is_some() {
            break;
        }
    }
    (
        viewing(even.expect("an even-y viewing key")),
        viewing(odd.expect("an odd-y viewing key")),
    )
}

fn merge_encryption() -> Value {
    let tx = viewing(41);
    let user = viewing(53);
    let stranger = viewing(67);

    let (merge_keystream, tx_public) = tx
        .encrypt_verifiable(&user.pubkey(), &zeros(KEYSTREAM_LEN))
        .expect("merge keystream");

    let shared = sha256_be(b"cert/merge shared secret");
    let mut symmetric_keystream = zeros(KEYSTREAM_LEN);
    symmetric_apply(&shared, MERGE_INFO, &mut symmetric_keystream).expect("symmetric keystream");

    // A single flipped bit of the Poseidon shared secret must reach the whole
    // keystream; the key schedule folds it through three hashes.
    let mut flipped_shared = shared;
    flipped_shared[31] ^= 0x01;
    let mut flipped_keystream = zeros(KEYSTREAM_LEN);
    symmetric_apply(&flipped_shared, MERGE_INFO, &mut flipped_keystream)
        .expect("flipped shared keystream");

    // `pack_info` splits the label at 31 bytes and writes its length into the
    // top byte of the low limb, so these labels probe the split, the position
    // within a limb, and the length prefix separately.
    let info_packing: Vec<Value> = [
        vec![],
        b"a".to_vec(),
        b"b".to_vec(),
        [b'a'; 31].to_vec(),
        {
            let mut info = [b'a'; 32].to_vec();
            info[31] = b'b';
            info
        },
        {
            let mut info = [b'a'; 32].to_vec();
            info[0] = b'b';
            info
        },
    ]
    .into_iter()
    .map(|info| {
        let mut buffer = zeros(KEYSTREAM_LEN);
        symmetric_apply(&shared, &info, &mut buffer).expect("labelled keystream");
        json!({
            "infoBytes": hex(&info),
            "keystreamBytes": hex(&buffer),
        })
    })
    .collect();

    // `merge_ciphertext_hash` right-aligns the trailing partial chunk into its
    // field element. A left-aligning port matches on the exact multiples of 16
    // and diverges everywhere else.
    let chunking: Vec<Value> = [1usize, 15, 16, 17, 31, 32, 33, 47, 71]
        .into_iter()
        .map(|length| {
            let ciphertext: Vec<u8> = (0..length).map(|index| (index * 11 + 3) as u8).collect();
            json!({
                "length": length,
                "ciphertextBytes": hex(&ciphertext),
                "hashBytes": hex(&merge_ciphertext_hash(&ciphertext).expect("ciphertext hash")),
            })
        })
        .collect();

    let (even, odd) = keys_by_prefix();
    let contributions: Vec<Value> = [even, odd]
        .into_iter()
        .map(|key| {
            let contribution =
                merge_public_contribution(&key.pubkey(), &[7u8; 32]).expect("public contribution");
            json!({
                "publicKeyBytes": hex(key.pubkey().as_bytes()),
                "yIsOdd": key.pubkey().y_is_odd(),
                "lowBytes": hex(&contribution.tx_viewing_pk_lo),
                "highBytes": hex(&contribution.tx_viewing_pk_hi),
                "ciphertextHashBytes": hex(&contribution.ciphertext_hash),
            })
        })
        .collect();

    let plaintext: Vec<u8> = (0..71u8).collect();
    let (ciphertext, _) = tx
        .encrypt_verifiable(&user.pubkey(), &plaintext)
        .expect("merge ciphertext");
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 0xff;

    json!({
        "keystreamLength": KEYSTREAM_LEN,
        "txSecretBytes": hex(&secret32(41)),
        "userSecretBytes": hex(&secret32(53)),
        "strangerSecretBytes": hex(&secret32(67)),
        "userPublicKeyBytes": hex(user.pubkey().as_bytes()),
        "txViewingPublicKeyBytes": hex(tx_public.as_bytes()),
        "ecdhBytes": hex(&tx.ecdh(&user.pubkey()).expect("merge ecdh")),
        "ecdhReverseBytes": hex(&user.ecdh(&tx_public).expect("reverse merge ecdh")),
        "mergeKeystreamBytes": hex(&merge_keystream),
        "symmetricSharedSecretBytes": hex(&shared),
        "symmetricKeystreamBytes": hex(&symmetric_keystream),
        "flippedSharedSecretBytes": hex(&flipped_shared),
        "flippedSharedKeystreamBytes": hex(&flipped_keystream),
        "infoPacking": info_packing,
        "ciphertextHashChunking": chunking,
        "publicContributions": contributions,
        "plaintextBytes": hex(&plaintext),
        "ciphertextBytes": hex(&ciphertext),
        "recoveredBytes": hex(
            &user.decrypt_verifiable(&tx_public, &ciphertext).expect("merge decrypt"),
        ),
        "wrongUserRecoveredBytes": hex(
            &stranger
                .decrypt_verifiable(&tx_public, &ciphertext)
                .expect("stranger merge decrypt"),
        ),
        "wrongTxKeyRecoveredBytes": hex(
            &user
                .decrypt_verifiable(&stranger.pubkey(), &ciphertext)
                .expect("wrong ephemeral merge decrypt"),
        ),
        "tamperedCiphertextBytes": hex(&tampered),
        "tamperedRecoveredBytes": hex(
            &user.decrypt_verifiable(&tx_public, &tampered).expect("tampered merge decrypt"),
        ),
        "tamperedHashBytes": hex(&merge_ciphertext_hash(&tampered).expect("tampered hash")),
    })
}

/// What Rust guarantees about secret ownership, so the TypeScript K8 suite
/// asserts against measured behaviour rather than against its own design.
fn secret_lifecycle() -> Value {
    let key = viewing(11);
    let original = *key.secret_bytes();
    let mut exported = key.secret_bytes();
    exported.fill(0);
    let viewing_independent = *key.secret_bytes() == original;

    let signing = SigningKey::from_bytes(&secret32(3)).expect("seeded p256 secret is in range");
    let signing_original = *signing.secret_bytes();
    let mut signing_exported = signing.secret_bytes();
    signing_exported.fill(0);
    let signing_independent = *signing.secret_bytes() == signing_original;

    let clone = key.clone();
    let clone_matches = *clone.secret_bytes() == original;

    json!({
        "viewingSecretExportIsIndependent": viewing_independent,
        "signingSecretExportIsIndependent": signing_independent,
        // `Clone` on `ViewingKey` duplicates the secret into a second live
        // buffer. TypeScript has no clone; `ShieldedKeypair.viewingKey()` is the
        // closest analogue and it copies too.
        "viewingKeyCloneCarriesSecret": clone_matches,
        // Rust relies on `Zeroizing` and `Drop`; there is no caller-invoked
        // destruction, so TypeScript's `destroy()` has no Rust counterpart to
        // be certified against and is measured against the threat model instead.
        "rustHasExplicitDestroy": false,
        // `NullifierKey::secret()` hands back `&[u8; 31]`, a borrow of live key
        // material, where TypeScript returns an owned copy. Recorded as a
        // deliberate difference in TypeScript's favour.
        "nullifierSecretAccessor": "borrow",
        "nullifierSecretBytes": hex(NullifierKey::from_secret([5u8; BLINDING_LEN]).secret()),
    })
}

/// A viewing-key backend that is not a `ViewingKey`: it holds key material
/// behind its own boundary and exposes only the trait. Implementing the trait
/// here is the compile-time half of K9 -- if a method gains a signature a
/// custodial backend cannot satisfy, or the trait starts demanding secret
/// export, this stops compiling.
struct BackendViewingKey {
    inner: ViewingKey,
}

impl ViewingKeyTrait for BackendViewingKey {
    fn pubkey(&self) -> P256Pubkey {
        self.inner.pubkey()
    }

    fn ecdh(&self, counterparty: &P256Pubkey) -> Result<[u8; 32], KeypairError> {
        self.inner.ecdh(counterparty)
    }

    fn get_sender_view_tag(&self, tx_count: u64) -> Result<ViewTag, KeypairError> {
        self.inner.get_sender_view_tag(tx_count)
    }

    fn get_recipient_request_view_tag(&self, request_count: u64) -> Result<ViewTag, KeypairError> {
        self.inner.get_recipient_request_view_tag(request_count)
    }

    fn get_merge_view_tag(&self, merge_count: u64) -> Result<ViewTag, KeypairError> {
        self.inner.get_merge_view_tag(merge_count)
    }

    fn get_send_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<ViewTag, KeypairError> {
        self.inner.get_send_shared_view_tag(counterparty, i)
    }

    fn get_recipient_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<ViewTag, KeypairError> {
        self.inner.get_recipient_shared_view_tag(counterparty, i)
    }

    fn recipient_bootstrap_view_tag(&self) -> ViewTag {
        self.inner.recipient_bootstrap_view_tag()
    }

    fn get_transaction_viewing_key(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<ViewingKey, KeypairError> {
        self.inner.get_transaction_viewing_key(first_nullifier)
    }

    fn encrypt_slot(
        &self,
        recipient_pubkey: &P256Pubkey,
        plaintext: &[u8],
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        self.inner
            .encrypt_slot(recipient_pubkey, plaintext, salt, slot_index)
    }

    fn decrypt_utxo(
        &self,
        ciphertext: &[u8],
        tx_viewing_pubkey: &P256Pubkey,
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        self.inner
            .decrypt_utxo(ciphertext, tx_viewing_pubkey, salt, slot_index)
    }

    fn decrypt_slot_ephemeral(
        &self,
        recipient_pubkey: &P256Pubkey,
        ciphertext: &[u8],
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        self.inner
            .decrypt_slot_ephemeral(recipient_pubkey, ciphertext, salt, slot_index)
    }

    fn encrypt_verifiable(
        &self,
        user_viewing_pk: &P256Pubkey,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, P256Pubkey), KeypairError> {
        self.inner.encrypt_verifiable(user_viewing_pk, plaintext)
    }

    fn decrypt_verifiable(
        &self,
        tx_viewing_pubkey: &P256Pubkey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KeypairError> {
        self.inner.decrypt_verifiable(tx_viewing_pubkey, ciphertext)
    }
}

/// Every `fn` declared directly in `pub trait <name>` in `path`. Reading the
/// source is what makes the recorded list exhaustive: a method added with a
/// default body would satisfy the impl above without appearing in it.
fn trait_methods(path: &str, name: &str) -> Vec<String> {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(path),
    )
    .expect("trait source");
    let header = format!("pub trait {name} {{\n");
    let start = source.find(&header).expect("trait declaration") + header.len();
    let body = &source[start..];
    let end = body.find("\n}\n").expect("trait terminator");
    body[..end]
        .lines()
        .filter_map(|line| line.strip_prefix("    fn "))
        .filter_map(|line| line.split(['(', '<']).next())
        .map(str::to_owned)
        .collect()
}

/// K9. The trait surfaces are the deployment boundary: what a wallet may ask a
/// key backend for, and by omission what it may not. The recorded TypeScript
/// name against each Rust method is the declared correspondence, so a rename on
/// either side shows up as a failure rather than as a silently missing method.
fn capability_boundary() -> Value {
    let backend = BackendViewingKey { inner: viewing(11) };
    let recipient = viewing(23);
    let keypair = ShieldedKeypair::from_keys(
        SigningKey::from_bytes(&secret32(3)).expect("seeded p256 secret"),
        viewing(11),
    )
    .expect("shielded keypair");

    // The operations a wallet drives through the trait, run against a backend
    // that is not a `ViewingKey`, so the surface is certified as sufficient
    // rather than merely declared.
    let through_backend = backend
        .encrypt_slot(&recipient.pubkey(), b"cert/backend", BASE_SALT, BASE_SLOT)
        .expect("backend encrypt");
    let direct = viewing(11)
        .encrypt_slot(&recipient.pubkey(), b"cert/backend", BASE_SALT, BASE_SLOT)
        .expect("direct encrypt");

    let viewing_rust = trait_methods("traits/view_key.rs", "ViewingKeyTrait");
    let keypair_rust = trait_methods("traits/shielded_keypair.rs", "ShieldedKeypairTrait");
    // `zip` truncates, so a method added to either trait would drop out of the
    // recorded mapping instead of failing. These bound the parsed lists.
    assert_eq!(viewing_rust.len(), 14, "ViewingKeyTrait changed size");
    assert_eq!(keypair_rust.len(), 10, "ShieldedKeypairTrait changed size");

    let viewing_methods: Vec<Value> = viewing_rust
        .into_iter()
        .zip([
            "publicKey",
            "ecdh",
            "senderViewTag",
            "recipientRequestViewTag",
            "mergeViewTag",
            "sendSharedViewTag",
            "recipientSharedViewTag",
            "recipientBootstrapViewTag",
            "transactionViewingKey",
            "encryptSlot",
            "decryptUtxo",
            "decryptSlotEphemeral",
            "encryptVerifiable",
            "decryptVerifiable",
        ])
        .map(|(rust, typescript)| json!({ "rust": rust, "typescript": typescript }))
        .collect();

    // `sign` and `try_sign` are one method in TypeScript: Rust's `sign` panics
    // on a bad P256 prehash length and `try_sign` returns the error, while a
    // TypeScript throw is the same control flow as the `Result`. The mapping
    // records `try_sign` as the counterpart and `sign` as absent.
    let keypair_methods: Vec<Value> = keypair_rust
        .into_iter()
        .zip([
            Some("signingPublicKey"),
            Some("viewingPublicKey"),
            Some("curve"),
            Some("shieldedAddress"),
            Some("ownerHash"),
            Some("compressedAddress"),
            None,
            Some("sign"),
            Some("nullifier"),
            Some("nullifierPublicKey"),
        ])
        .map(|(rust, typescript)| json!({ "rust": rust, "typescript": typescript }))
        .collect();

    json!({
        "viewingKeyTrait": viewing_methods,
        "shieldedKeypairTrait": keypair_methods,
        // The trait declares no constructor and no secret export, which is what
        // lets a custodial backend implement it. The list above is read out of
        // the trait source, so the absence is measured, not asserted.
        "excludedFromViewingKeyTrait": ["from_bytes", "from_seed", "generate", "secret_bytes"],
        "backendMatchesDirectKey": through_backend == direct,
        // A full keypair satisfies both traits, so it stands in wherever a
        // viewing-key backend is required.
        "shieldedKeypairIsViewingBackend":
            ViewingKeyTrait::pubkey(&keypair) == viewing(11).pubkey()
                && ShieldedKeypairTrait::nullifier_pubkey(&keypair).is_ok(),
        // Rust's trait is synchronous. The owner's 2026-07-26 ruling that an
        // out-of-process viewing-key backend is unsupported keeps TypeScript on
        // the same shape, so a call site never awaits a view tag.
        "synchronous": true,
    })
}

fn ledger_entry(case: &str, boundary: &str, error: &KeypairError) -> Value {
    json!({
        "case": case,
        "boundary": boundary,
        "rustVariant": variant_name(error),
        "display": error.to_string(),
    })
}

fn variant_name(error: &KeypairError) -> &'static str {
    match error {
        KeypairError::InvalidPublicKey => "InvalidPublicKey",
        KeypairError::InvalidSecretKey => "InvalidSecretKey",
        KeypairError::ZeroScalar => "ZeroScalar",
        KeypairError::InvalidSignatureType(_) => "InvalidSignatureType",
        KeypairError::NotEd25519 => "NotEd25519",
        KeypairError::Hkdf => "Hkdf",
        KeypairError::Poseidon(_) => "Poseidon",
        KeypairError::FieldElementTooLong => "FieldElementTooLong",
        KeypairError::InvalidPrehashLength(_) => "InvalidPrehashLength",
        KeypairError::InfoTooLong => "InfoTooLong",
    }
}

fn expect_err<T>(result: Result<T, KeypairError>) -> KeypairError {
    match result {
        Ok(_) => panic!("expected the operation to be refused"),
        Err(error) => error,
    }
}

/// The closed K10 ledger. Each case is one row of the suite's list, and each
/// row says whether Rust reaches it, which boundary raises it, and what it
/// renders as. Rows Rust cannot reach are recorded as such rather than omitted:
/// an absent row reads as an untested one.
fn error_ledger() -> Value {
    let signing = SigningKey::from_bytes(&secret32(3)).expect("seeded p256 secret is in range");
    let p256_public = signing.pubkey();
    let mut bad_point = *p256_public.as_bytes();
    bad_point[PUBLIC_KEY_LEN - 1] ^= 0xff;
    let mut bad_prefix = *p256_public.as_bytes();
    bad_prefix[0] = 9;

    let plaintext = b"cert/ledger plaintext".to_vec();
    let sender = viewing(11);
    let recipient = viewing(23);
    let ciphertext = sender
        .encrypt_slot(&recipient.pubkey(), &plaintext, BASE_SALT, BASE_SLOT)
        .expect("ledger ciphertext");
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 0xff;

    let mut overlong = plaintext.clone();
    let info_too_long = expect_err(symmetric_apply(
        &sha256_be(b"cert/merge shared secret"),
        &[0x6c; 63],
        &mut overlong,
    ));

    json!({
        "raised": [
            ledger_entry(
                "invalidSecretKey",
                "SigningKey::from_bytes",
                &expect_err(SigningKey::from_bytes(&[0u8; 32])),
            ),
            ledger_entry(
                "invalidPublicKey",
                "PublicKey::from_bytes",
                &expect_err(PublicKey::from_bytes(bad_point)),
            ),
            ledger_entry(
                "wrongSignatureType",
                "PublicKey::from_bytes",
                &expect_err(PublicKey::from_bytes(bad_prefix)),
            ),
            ledger_entry(
                "unsupportedCapability",
                "ShieldedKeypair::to_solana_keypair",
                &expect_err(
                    ShieldedKeypair::from_keys(
                        SigningKey::from_bytes(&secret32(3)).expect("seeded p256 secret"),
                        viewing(11),
                    )
                    .expect("shielded keypair")
                    .to_solana_keypair(),
                ),
            ),
            ledger_entry(
                "fieldFailure",
                "NullifierKey::nullifier",
                &expect_err(
                    NullifierKey::from_secret([5u8; BLINDING_LEN])
                        .nullifier(&[0xff; 32], &[3u8; BLINDING_LEN]),
                ),
            ),
            ledger_entry(
                "invalidPrehashLength",
                "SigningKey::try_sign",
                &expect_err(signing.try_sign(&[7u8; 31])),
            ),
            ledger_entry("infoTooLong", "merge::symmetric_apply", &info_too_long),
        ],
        "badPointBytes": hex(&bad_point),
        "badPrefixBytes": hex(&bad_prefix),
        // Rows the suite names that current Rust cannot reach through its public
        // API, with what makes them unreachable.
        "unreachable": [
            {
                "case": "zeroScalar",
                "reason": "reachable only if an HKDF-derived P256 scalar lands on zero, which no fixed input produces",
            },
            {
                "case": "hkdfFailure",
                "reason": "HKDF-Expand fails only above 255 hash blocks; every call site asks for 31, 32, 44 or 48 bytes",
            },
        ],
        // Rows that are not errors at all. CTR carries no authentication tag,
        // so integrity comes from the proof-committed UTXO hash and a wrong key,
        // slot, salt or tampered ciphertext all decrypt successfully to garbage.
        // A port that raises here would reject transactions the protocol accepts.
        "nonErrors": {
            "malformedSignatureVerifies": signing.verify(&sha256_be(b"cert/msg"), &[0u8; 64]),
            "wrongSlotRecoveredBytes": hex(
                &recipient
                    .decrypt_utxo(&ciphertext, &sender.pubkey(), BASE_SALT, BASE_SLOT + 1)
                    .expect("wrong slot decrypt"),
            ),
            "wrongSaltRecoveredBytes": hex(
                &recipient
                    .decrypt_utxo(&ciphertext, &sender.pubkey(), [0x5b; SALT_LEN], BASE_SLOT)
                    .expect("wrong salt decrypt"),
            ),
            "tamperedRecoveredBytes": hex(
                &recipient
                    .decrypt_utxo(&tampered, &sender.pubkey(), BASE_SALT, BASE_SLOT)
                    .expect("tampered decrypt"),
            ),
            "plaintextBytes": hex(&plaintext),
        },
        // Every variant renders without payload beyond the integers the enum
        // carries, which is what bounds Rust's disclosure surface.
        "displaysCarryNoBytes": true,
    })
}

fn document() -> Value {
    let mut root = Map::new();
    root.insert("schema".into(), json!("zolana-keypair-crypto-cert-v1"));
    root.insert(
        "source".into(),
        json!("sdk-libs/keypair/tests/crypto_certification.rs"),
    );
    root.insert("suites".into(), json!(["K6", "K7", "K8", "K9", "K10"]));
    root.insert(
        "note".into(),
        json!(
            "Every value is produced by the current zolana-keypair crate through \
             its public API. Secrets are fixed test material. Regenerate with \
             UPDATE_KEYPAIR_VECTORS=1."
        ),
    );
    root.insert("testOnlySecret".into(), json!(true));
    root.insert("transferEncryption".into(), transfer_encryption());
    root.insert("mergeEncryption".into(), merge_encryption());
    root.insert("secretLifecycle".into(), secret_lifecycle());
    root.insert("capabilityBoundary".into(), capability_boundary());
    root.insert("errorLedger".into(), error_ledger());
    Value::Object(root)
}

#[test]
fn committed_vectors_match_current_rust() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTOR_PATH);
    let generated = format!("{}\n", serde_json::to_string_pretty(&document()).unwrap());

    if std::env::var_os("UPDATE_KEYPAIR_VECTORS").is_some() {
        std::fs::write(&path, &generated).expect("write certification vectors");
        return;
    }

    let committed = std::fs::read_to_string(&path).expect(
        "sdk-libs/ts/vectors/keypair-crypto-cert-v1.json is missing; regenerate with \
         UPDATE_KEYPAIR_VECTORS=1",
    );
    assert_eq!(
        committed, generated,
        "committed certification vectors drifted from the current Rust crate",
    );
}

/// The generator's own preconditions. If any of these stops holding, the
/// vectors above stop meaning what the TypeScript suites read them as.
#[test]
fn vectors_rest_on_the_properties_they_claim() {
    let sender = viewing(11);
    let recipient = viewing(23);

    // A keystream is only evidence about the key schedule if encrypting zeros
    // really returns it: XOR with a known plaintext must reproduce the recorded
    // ciphertext.
    let plaintext = b"cert/transfer utxo bundle".to_vec();
    let keystream = transfer_keystream(&sender, &recipient.pubkey(), BASE_SALT, BASE_SLOT);
    let ciphertext = sender
        .encrypt_slot(&recipient.pubkey(), &plaintext, BASE_SALT, BASE_SLOT)
        .expect("ciphertext");
    let xored: Vec<u8> = plaintext
        .iter()
        .zip(keystream.iter())
        .map(|(byte, key)| byte ^ key)
        .collect();
    assert_eq!(
        xored, ciphertext,
        "zero-plaintext output is not the keystream"
    );

    // Every boundary row must differ from the base row, or the row proves
    // nothing about the input it perturbs.
    let boundaries = transfer_encryption()["boundaries"].clone();
    let rows = boundaries.as_array().expect("boundary rows");
    let base = rows[0]["keystreamBytes"].clone();
    for row in &rows[1..] {
        assert_ne!(
            row["keystreamBytes"], base,
            "boundary row {} does not change the keystream",
            row["case"],
        );
    }

    let merge = merge_encryption();
    assert_ne!(
        merge["symmetricKeystreamBytes"], merge["flippedSharedKeystreamBytes"],
        "a flipped shared-secret bit does not reach the merge keystream",
    );
    let labels = merge["infoPacking"].as_array().expect("info rows");
    let mut seen = std::collections::BTreeSet::new();
    for row in labels {
        assert!(
            seen.insert(row["keystreamBytes"].to_string()),
            "two info labels share a keystream",
        );
    }
}
