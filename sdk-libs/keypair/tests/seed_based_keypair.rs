use ed25519_dalek_bip32::ExtendedSigningKey;
use hkdf::hmac::{Hmac, Mac};
use p256::elliptic_curve::{Field, PrimeField};
use p256::Scalar;
use sha2::Sha512;
use solana_derivation_path::DerivationPath;
use solana_keypair::{seed_derivable::keypair_from_seed_and_derivation_path, Signer};
use solana_seed_phrase::generate_seed_from_seed_phrase_and_passphrase;
use zolana_keypair::{
    constants::BLINDING_LEN,
    derivation::{ed25519_derivation_message, ED25519_DERIVATION_MSG},
    hash, CompressedShieldedAddress, Curve, KeypairError, NullifierKey, P256Pubkey, PublicKey,
    ShieldedAddress, ShieldedKeypair, ShieldedKeypairTrait, SigningKey, ViewingKey,
};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const TSPP_COIN_TYPE: u32 = 1392955331;

const NIST256P1_MASTER_HMAC_KEY: &[u8] = b"Nist256p1 seed";

fn solana_path(account: u32) -> String {
    format!("m/44'/501'/{account}'/0'")
}

fn tspp_path(account: u32, role: u32) -> String {
    format!("m/44'/{TSPP_COIN_TYPE}'/{account}'/{role}'/0'")
}

fn derive_node_bytes(seed: &[u8], path: &str) -> [u8; 32] {
    let path = DerivationPath::from_absolute_path_str(path).expect("valid derivation path");
    ExtendedSigningKey::from_seed(seed)
        .expect("root node from seed")
        .derive(&path)
        .expect("hardened derivation")
        .signing_key
        .to_bytes()
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn split_digest(digest: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let (left, right) = digest.split_at(32);
    (
        left.try_into().expect("32-byte digest half"),
        right.try_into().expect("32-byte digest half"),
    )
}

fn nist256p1_master(seed: &[u8]) -> (Scalar, [u8; 32]) {
    let mut digest = hmac_sha512(NIST256P1_MASTER_HMAC_KEY, seed);
    loop {
        let (key_bytes, chain) = split_digest(&digest);
        let key: Option<Scalar> = Scalar::from_repr(key_bytes.into()).into();
        if let Some(key) = key.filter(|scalar| !bool::from(scalar.is_zero())) {
            return (key, chain);
        }
        digest = hmac_sha512(NIST256P1_MASTER_HMAC_KEY, &digest);
    }
}

fn nist256p1_hardened_child(key: &Scalar, chain: &[u8; 32], index: u32) -> (Scalar, [u8; 32]) {
    let hardened = (0x8000_0000u32 + index).to_be_bytes();
    let mut data = Vec::with_capacity(37);
    data.push(0u8);
    data.extend_from_slice(&key.to_bytes());
    data.extend_from_slice(&hardened);
    loop {
        let digest = hmac_sha512(chain, &data);
        let (tweak_bytes, child_chain) = split_digest(&digest);
        let tweak: Option<Scalar> = Scalar::from_repr(tweak_bytes.into()).into();
        if let Some(tweak) = tweak {
            let child_key = tweak + key;
            if !bool::from(child_key.is_zero()) {
                return (child_key, child_chain);
            }
        }
        data.clear();
        data.push(1u8);
        data.extend_from_slice(&child_chain);
        data.extend_from_slice(&hardened);
    }
}

fn derive_node_p256_bytes(seed: &[u8], path: &[u32]) -> [u8; 32] {
    let (mut key, mut chain) = nist256p1_master(seed);
    for &index in path {
        let (child_key, child_chain) = nist256p1_hardened_child(&key, &chain, index);
        key = child_key;
        chain = child_chain;
    }
    key.to_bytes().into()
}

fn nullifier_secret(node: &[u8; 32]) -> [u8; BLINDING_LEN] {
    let (_, tail) = node.split_first().expect("node key is nonempty");
    tail.try_into().expect("31-byte nullifier secret")
}

struct SeedBasedShieldedKeypair {
    signing_key: SigningKey,
    nullifier_key: NullifierKey,
    viewing_key: ViewingKey,
}

impl SeedBasedShieldedKeypair {
    fn from_seed_phrase(phrase: &str, account: u32) -> Self {
        let seed = generate_seed_from_seed_phrase_and_passphrase(phrase, "");
        let signing_bytes = derive_node_bytes(&seed, &solana_path(account));
        let nullifier_node = derive_node_bytes(&seed, &tspp_path(account, 1));
        let viewing_node = derive_node_p256_bytes(&seed, &[44, TSPP_COIN_TYPE, account, 2, 0]);
        Self {
            signing_key: SigningKey::from_ed25519_bytes(&signing_bytes),
            nullifier_key: NullifierKey::from_secret(nullifier_secret(&nullifier_node)),
            viewing_key: ViewingKey::from_bytes(&viewing_node)
                .expect("node_p256 keys are valid P-256 scalars by construction"),
        }
    }
}

impl ShieldedKeypairTrait for SeedBasedShieldedKeypair {
    fn signing_pubkey(&self) -> PublicKey {
        self.signing_key.pubkey()
    }

    fn viewing_pubkey(&self) -> P256Pubkey {
        self.viewing_key.pubkey()
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn shielded_address(&self) -> Result<ShieldedAddress, KeypairError> {
        Ok(ShieldedAddress {
            signing_pubkey: self.signing_key.pubkey(),
            nullifier_pubkey: self.nullifier_key.pubkey()?,
            viewing_pubkey: self.viewing_key.pubkey(),
        })
    }

    fn owner_hash(&self) -> Result<[u8; 32], KeypairError> {
        hash::owner_hash(&self.signing_key.pubkey(), &self.nullifier_key.pubkey()?)
    }

    fn compressed_address(&self) -> Result<CompressedShieldedAddress, KeypairError> {
        Ok(CompressedShieldedAddress {
            owner_hash: self.owner_hash()?,
            viewing_pubkey: self.viewing_key.pubkey(),
        })
    }

    fn sign_message(&self, message: &[u8]) -> Result<[u8; 64], KeypairError> {
        self.signing_key.sign_message(message)
    }

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<[u8; 64], KeypairError> {
        self.signing_key.sign_hash(hash)
    }

    fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; 32],
    ) -> Result<[u8; 32], KeypairError> {
        self.nullifier_key.nullifier(utxo_hash, blinding)
    }

    fn nullifier_key(&self) -> NullifierKey {
        self.nullifier_key.clone()
    }
}

#[test]
fn seed_based_signing_key_matches_solana_derivation() {
    let keypair = SeedBasedShieldedKeypair::from_seed_phrase(TEST_MNEMONIC, 0);

    let seed = generate_seed_from_seed_phrase_and_passphrase(TEST_MNEMONIC, "");
    let solana = keypair_from_seed_and_derivation_path(
        &seed,
        Some(DerivationPath::new_bip44(Some(0), Some(0))),
    )
    .expect("solana keypair derivation");

    assert_eq!(
        keypair.signing_pubkey(),
        PublicKey::from_ed25519(&solana.pubkey().to_bytes())
    );
}

#[test]
fn seed_based_keypair_matches_reference_parts() {
    let keypair = SeedBasedShieldedKeypair::from_seed_phrase(TEST_MNEMONIC, 0);

    let seed = generate_seed_from_seed_phrase_and_passphrase(TEST_MNEMONIC, "");
    let signing_reference =
        SigningKey::from_ed25519_bytes(&derive_node_bytes(&seed, &solana_path(0)));
    let nullifier_reference = NullifierKey::from_secret(nullifier_secret(&derive_node_bytes(
        &seed,
        &tspp_path(0, 1),
    )));
    let viewing_reference = ViewingKey::from_bytes(&derive_node_p256_bytes(
        &seed,
        &[44, TSPP_COIN_TYPE, 0, 2, 0],
    ))
    .expect("node_p256 keys are valid P-256 scalars by construction");

    assert_eq!(keypair.signing_pubkey(), signing_reference.pubkey());
    assert_eq!(keypair.viewing_pubkey(), viewing_reference.pubkey());
    assert_eq!(keypair.curve(), Curve::Ed25519);
    assert_eq!(
        *keypair.nullifier_key().secret(),
        *nullifier_reference.secret()
    );
    assert_eq!(
        keypair.nullifier_pubkey().unwrap(),
        nullifier_reference.pubkey().unwrap()
    );

    let expected_owner_hash = hash::owner_hash(
        &signing_reference.pubkey(),
        &nullifier_reference.pubkey().unwrap(),
    )
    .unwrap();
    assert_eq!(keypair.owner_hash().unwrap(), expected_owner_hash);
    assert_eq!(
        keypair.shielded_address().unwrap(),
        ShieldedAddress {
            signing_pubkey: signing_reference.pubkey(),
            nullifier_pubkey: nullifier_reference.pubkey().unwrap(),
            viewing_pubkey: viewing_reference.pubkey(),
        }
    );
    assert_eq!(
        keypair.compressed_address().unwrap(),
        CompressedShieldedAddress {
            owner_hash: expected_owner_hash,
            viewing_pubkey: viewing_reference.pubkey(),
        }
    );

    let utxo_hash = [1u8; 32];
    let blinding = [2u8; 32];
    assert_eq!(
        keypair.nullifier(&utxo_hash, &blinding).unwrap(),
        nullifier_reference
            .nullifier(&utxo_hash, &blinding)
            .unwrap()
    );
}

#[test]
fn seed_based_keypair_is_deterministic_and_account_separated() {
    let first = SeedBasedShieldedKeypair::from_seed_phrase(TEST_MNEMONIC, 0);
    let second = SeedBasedShieldedKeypair::from_seed_phrase(TEST_MNEMONIC, 0);
    assert_eq!(
        first.shielded_address().unwrap(),
        second.shielded_address().unwrap()
    );

    let other_account = SeedBasedShieldedKeypair::from_seed_phrase(TEST_MNEMONIC, 1);
    assert_ne!(other_account.signing_pubkey(), first.signing_pubkey());
    assert_ne!(
        other_account.nullifier_pubkey().unwrap(),
        first.nullifier_pubkey().unwrap()
    );
    assert_ne!(other_account.viewing_pubkey(), first.viewing_pubkey());

    let signature_rail = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(
        &first.signing_key.secret_bytes(),
    ))
    .expect("signature-rail keypair");
    assert_eq!(signature_rail.signing_pubkey(), first.signing_pubkey());
    assert_ne!(
        signature_rail.nullifier_key.pubkey().unwrap(),
        first.nullifier_pubkey().unwrap()
    );
    assert_ne!(signature_rail.viewing_pubkey(), first.viewing_pubkey());
}

#[test]
fn seed_based_keypair_signs_and_guards_derivation_inputs() {
    let keypair = SeedBasedShieldedKeypair::from_seed_phrase(TEST_MNEMONIC, 0);

    let msg = b"private tx hash binding";
    let signature = keypair.sign_message(msg).unwrap();
    assert!(keypair.signing_pubkey().verify_message(msg, &signature));

    let signer = keypair.signing_pubkey().as_ed25519().unwrap();
    assert_eq!(
        keypair.sign_message(ED25519_DERIVATION_MSG),
        Err(KeypairError::DerivationInput)
    );
    assert_eq!(
        keypair.sign_message(&ed25519_derivation_message(&signer)),
        Err(KeypairError::DerivationInput)
    );
    assert_eq!(keypair.sign_hash(&[7u8; 32]), Err(KeypairError::NotP256));
}

#[test]
fn slip10_nist256p1_matches_official_vectors() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let (master_key, master_chain) = nist256p1_master(&seed);
    assert_eq!(
        hex::encode(master_key.to_bytes()),
        "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2"
    );
    assert_eq!(
        hex::encode(master_chain),
        "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea"
    );

    let (child_key, child_chain) = nist256p1_hardened_child(&master_key, &master_chain, 0);
    assert_eq!(
        hex::encode(child_key.to_bytes()),
        "6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c"
    );
    assert_eq!(
        hex::encode(child_chain),
        "3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11"
    );

    let (retry_key, retry_chain) = nist256p1_hardened_child(&master_key, &master_chain, 28578);
    assert_eq!(
        hex::encode(retry_key.to_bytes()),
        "06f0db126f023755d0b8d86d4591718a5210dd8d024e3e14b6159d63f53aa669"
    );
    assert_eq!(
        hex::encode(retry_chain),
        "e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2"
    );

    let long_seed = hex::decode(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2\
         9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
    )
    .unwrap();
    let (long_key, long_chain) = nist256p1_master(&long_seed);
    assert_eq!(
        hex::encode(long_key.to_bytes()),
        "eaa31c2e46ca2962227cf21d73a7ef0ce8b31c756897521eb6c7b39796633357"
    );
    assert_eq!(
        hex::encode(long_chain),
        "96cd4465a9644e31528eda3592aa35eb39a9527769ce1855beafc1b81055e75d"
    );

    let retry_seed =
        hex::decode("a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446").unwrap();
    let (seed_retry_key, seed_retry_chain) = nist256p1_master(&retry_seed);
    assert_eq!(
        hex::encode(seed_retry_key.to_bytes()),
        "3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f"
    );
    assert_eq!(
        hex::encode(seed_retry_chain),
        "7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c"
    );
}

#[test]
fn seed_based_viewing_key_matches_pinned_vectors() {
    let seed = generate_seed_from_seed_phrase_and_passphrase(TEST_MNEMONIC, "");
    let cases = [
        (
            0u32,
            "1694bc1c8a456511d0364e26c71409b4912c5b2ff56bed3fc9c706e066496a54",
            "03170ee9cf7a6f1ad811bd2019d386f67ce337458e0bf585c3cad7ddac85373e32",
        ),
        (
            1u32,
            "60a8c80b23007c79c1dcf1821446dc77e6fcd2bb3e747ddca629784adaf8fa18",
            "03bb3b5ea4e0a873297d1f80e2ee1ebfabf472129debca75fced4753a95769fe27",
        ),
    ];
    for (account, viewing_secret, viewing_pubkey) in cases {
        let node = derive_node_p256_bytes(&seed, &[44, TSPP_COIN_TYPE, account, 2, 0]);
        assert_eq!(hex::encode(node), viewing_secret);
        let viewing = ViewingKey::from_bytes(&node)
            .expect("node_p256 keys are valid P-256 scalars by construction");
        assert_eq!(hex::encode(viewing.pubkey().as_bytes()), viewing_pubkey);
    }
}
