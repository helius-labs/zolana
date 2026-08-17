use aws_sdk_kms::{
    operation::{
        get_public_key::GetPublicKeyOutput,
        sign::{SignError, SignInput, SignOutput},
    },
    primitives::Blob,
    types::{
        error::KmsInvalidStateException, KeySpec, KeyUsageType, MessageType, SigningAlgorithmSpec,
    },
    Client,
};
use aws_smithy_mocks::{mock, mock_client, Rule, RuleMode};
use ed25519_dalek::Signer;
use zolana_keypair::{
    constants::BLINDING_LEN,
    derivation::{self, INFO_NF_KEY_ED25519, INFO_VIEW_KEY_ED25519},
    hash,
    shielded::{CompressedShieldedAddress, ShieldedAddress},
    Curve, KeypairError, NullifierKey, P256Pubkey, PublicKey, ShieldedKeypairTrait, ViewingKey,
};

pub const KEY_ID: &str = "arn:aws:kms:us-east-1:111122223333:key/mock-ed25519";

const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

pub struct KmsEd25519Rules {
    pub get_public_key: Rule,
    pub sign: Rule,
}

fn get_public_key_rule(secret: &[u8; 32]) -> Rule {
    let verifying_key = ed25519_dalek::SigningKey::from_bytes(secret).verifying_key();
    let mut spki = ED25519_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(verifying_key.as_bytes());
    mock!(Client::get_public_key)
        .match_requests(|request| request.key_id() == Some(KEY_ID))
        .then_output(move || {
            GetPublicKeyOutput::builder()
                .key_id(KEY_ID)
                .public_key(Blob::new(spki.clone()))
                .key_spec(KeySpec::EccNistEdwards25519)
                .key_usage(KeyUsageType::SignVerify)
                .signing_algorithms(SigningAlgorithmSpec::Ed25519Sha512)
                .build()
        })
}

fn compute_sign_output(signing_key: &ed25519_dalek::SigningKey, request: &SignInput) -> SignOutput {
    let message = request.message().expect("sign request carries a message");
    let signature = signing_key.sign(message.as_ref());
    SignOutput::builder()
        .key_id(KEY_ID)
        .signature(Blob::new(signature.to_bytes().to_vec()))
        .signing_algorithm(SigningAlgorithmSpec::Ed25519Sha512)
        .build()
}

fn sign_rule(secret: &[u8; 32]) -> Rule {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret);
    mock!(Client::sign)
        .match_requests(|request| {
            request.key_id() == Some(KEY_ID)
                && request.message_type() == Some(&MessageType::Raw)
                && request.signing_algorithm() == Some(&SigningAlgorithmSpec::Ed25519Sha512)
        })
        .then_compute_output(move |request| compute_sign_output(&signing_key, request))
}

pub fn ed25519_client(secret: &[u8; 32]) -> (Client, KmsEd25519Rules) {
    let rules = KmsEd25519Rules {
        get_public_key: get_public_key_rule(secret),
        sign: sign_rule(secret),
    };
    let client = mock_client!(
        aws_sdk_kms,
        RuleMode::MatchAny,
        [&rules.get_public_key, &rules.sign]
    );
    (client, rules)
}

pub fn ed25519_client_failing_after_bootstrap(secret: &[u8; 32]) -> Client {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret);
    let seed_rule = mock!(Client::sign)
        .match_requests(|request| {
            request
                .message()
                .is_some_and(|message| derivation::is_derivation_input(message.as_ref()))
        })
        .then_compute_output(move |request| compute_sign_output(&signing_key, request));
    let fail_rule = mock!(Client::sign).then_error(|| {
        SignError::KmsInvalidStateException(
            KmsInvalidStateException::builder()
                .message("key is pending deletion")
                .build(),
        )
    });
    let get_public_key = get_public_key_rule(secret);
    mock_client!(
        aws_sdk_kms,
        RuleMode::MatchAny,
        [&get_public_key, &seed_rule, &fail_rule]
    )
}

pub struct KmsShieldedKeypair {
    runtime: tokio::runtime::Runtime,
    client: Client,
    key_id: String,
    signing_pubkey: PublicKey,
    nullifier_key: NullifierKey,
    viewing_key: ViewingKey,
}

impl KmsShieldedKeypair {
    pub fn bootstrap(client: Client, key_id: &str) -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("current-thread runtime");
        let public_key = runtime
            .block_on(client.get_public_key().key_id(key_id).send())
            .expect("GetPublicKey succeeds");
        assert_eq!(public_key.key_spec(), Some(&KeySpec::EccNistEdwards25519));
        assert_eq!(public_key.key_usage(), Some(&KeyUsageType::SignVerify));
        let spki = public_key.public_key().expect("SPKI public key");
        let ed25519_pubkey: [u8; 32] = spki
            .as_ref()
            .strip_prefix(ED25519_SPKI_PREFIX.as_slice())
            .expect("RFC 8410 ed25519 SPKI")
            .try_into()
            .expect("32-byte ed25519 public key");
        let envelope = derivation::ed25519_derivation_message(&ed25519_pubkey);
        let seed = runtime
            .block_on(
                client
                    .sign()
                    .key_id(key_id)
                    .message(Blob::new(envelope))
                    .message_type(MessageType::Raw)
                    .signing_algorithm(SigningAlgorithmSpec::Ed25519Sha512)
                    .send(),
            )
            .expect("Sign succeeds")
            .signature()
            .expect("signature blob")
            .as_ref()
            .to_vec();
        let (nullifier_key, viewing_key) = expand_roles(&seed);
        Self {
            runtime,
            client,
            key_id: key_id.to_string(),
            signing_pubkey: PublicKey::from_ed25519(&ed25519_pubkey),
            nullifier_key,
            viewing_key,
        }
    }
}

fn expand_roles(seed: &[u8]) -> (NullifierKey, ViewingKey) {
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, seed);
    let mut nullifier_secret = [0u8; BLINDING_LEN];
    hkdf.expand(INFO_NF_KEY_ED25519, &mut nullifier_secret)
        .expect("nullifier expand");
    let mut okm = [0u8; 48];
    hkdf.expand(INFO_VIEW_KEY_ED25519, &mut okm)
        .expect("viewing expand");
    let viewing_secret = viewing_secret_from_okm(&okm);
    (
        NullifierKey::from_secret(nullifier_secret),
        ViewingKey::from_bytes(&viewing_secret).expect("viewing key from expanded scalar"),
    )
}

#[allow(deprecated)]
fn viewing_secret_from_okm(okm: &[u8; 48]) -> [u8; 32] {
    use p256::elliptic_curve::{
        generic_array::{typenum::U48, GenericArray},
        hash2curve::FromOkm,
    };

    let scalar = p256::Scalar::from_okm(GenericArray::<u8, U48>::from_slice(okm));
    let nonzero = p256::NonZeroScalar::new(scalar).expect("nonzero viewing scalar");
    p256::SecretKey::from(nonzero).to_bytes().into()
}

impl ShieldedKeypairTrait for KmsShieldedKeypair {
    fn signing_pubkey(&self) -> PublicKey {
        self.signing_pubkey
    }

    fn viewing_pubkey(&self) -> P256Pubkey {
        self.viewing_key.pubkey()
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn shielded_address(&self) -> Result<ShieldedAddress, KeypairError> {
        Ok(ShieldedAddress {
            signing_pubkey: self.signing_pubkey,
            nullifier_pubkey: self.nullifier_key.pubkey()?,
            viewing_pubkey: self.viewing_key.pubkey(),
        })
    }

    fn owner_hash(&self) -> Result<[u8; 32], KeypairError> {
        hash::owner_hash(&self.signing_pubkey, &self.nullifier_key.pubkey()?)
    }

    fn compressed_address(&self) -> Result<CompressedShieldedAddress, KeypairError> {
        Ok(CompressedShieldedAddress {
            owner_hash: self.owner_hash()?,
            viewing_pubkey: self.viewing_key.pubkey(),
        })
    }

    fn sign_message(&self, message: &[u8]) -> Result<[u8; 64], KeypairError> {
        if derivation::is_derivation_input(message) {
            return Err(KeypairError::DerivationInput);
        }
        let output = self
            .runtime
            .block_on(
                self.client
                    .sign()
                    .key_id(&self.key_id)
                    .message(Blob::new(message.to_vec()))
                    .message_type(MessageType::Raw)
                    .signing_algorithm(SigningAlgorithmSpec::Ed25519Sha512)
                    .send(),
            )
            .map_err(|_| KeypairError::SigningFailed)?;
        output
            .signature()
            .ok_or(KeypairError::SigningFailed)?
            .as_ref()
            .try_into()
            .map_err(|_| KeypairError::SigningFailed)
    }

    fn sign_hash(&self, _hash: &[u8; 32]) -> Result<[u8; 64], KeypairError> {
        Err(KeypairError::NotP256)
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
