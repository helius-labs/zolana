use ed25519_dalek_bip32::ExtendedSigningKey;
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
        let viewing_node = derive_node_bytes(&seed, &tspp_path(account, 2));
        Self {
            signing_key: SigningKey::from_ed25519_bytes(&signing_bytes),
            nullifier_key: NullifierKey::from_secret(nullifier_secret(&nullifier_node)),
            viewing_key: ViewingKey::from_bytes(&viewing_node)
                .expect("derived viewing bytes are a valid P-256 scalar"),
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

    fn curve(&self) -> Result<Curve, KeypairError> {
        Ok(Curve::Ed25519)
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

    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], KeypairError> {
        self.signing_key.sign(msg)
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
    let viewing_reference = ViewingKey::from_bytes(&derive_node_bytes(&seed, &tspp_path(0, 2)))
        .expect("derived viewing bytes are a valid P-256 scalar");

    assert_eq!(keypair.signing_pubkey(), signing_reference.pubkey());
    assert_eq!(keypair.viewing_pubkey(), viewing_reference.pubkey());
    assert_eq!(keypair.curve().unwrap(), Curve::Ed25519);
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
    let signature = keypair.sign(msg).unwrap();
    assert!(keypair.signing_key.verify(msg, &signature));

    let signer = keypair.signing_pubkey().as_ed25519().unwrap();
    assert_eq!(
        keypair.sign(ED25519_DERIVATION_MSG),
        Err(KeypairError::DerivationInput)
    );
    assert_eq!(
        keypair.sign(&ed25519_derivation_message(&signer)),
        Err(KeypairError::DerivationInput)
    );
}
