use aws_sdk_kms::{
    operation::{
        derive_shared_secret::{DeriveSharedSecretError, DeriveSharedSecretOutput},
        get_public_key::GetPublicKeyOutput,
        sign::{SignError, SignInput, SignOutput},
    },
    primitives::Blob,
    types::{
        error::InvalidKeyUsageException, KeyAgreementAlgorithmSpec, KeySpec, KeyUsageType,
        MessageType, OriginType, SigningAlgorithmSpec,
    },
    Client,
};
use aws_smithy_mocks::{mock, mock_client, Rule, RuleMode};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use zolana_keypair::{
    constants::BLINDING_LEN,
    derivation::{self, INFO_NF_KEY_ECDH, P_DERIVE_SEC1},
    hash,
    shielded::{CompressedShieldedAddress, ShieldedAddress},
    Curve, KeypairError, NullifierKey, P256Pubkey, PublicKey, ShieldedKeypairTrait,
};

use super::codec;

pub const SIGN_KEY_ID: &str = "arn:aws:kms:us-east-1:111122223333:key/mock-p256-sign";

pub const VIEWING_KEY_ID: &str = "arn:aws:kms:us-east-1:111122223333:key/mock-p256-viewing";

pub const NULLIFIER_KEY_ID: &str = "arn:aws:kms:us-east-1:111122223333:key/mock-p256-nullifier";

pub struct P256Roots {
    pub sign: [u8; 32],
    pub viewing: [u8; 32],
    pub nullifier: [u8; 32],
}

pub struct P256Rules {
    pub get_public_key_sign: Rule,
    pub get_public_key_viewing: Rule,
    pub get_public_key_nullifier: Rule,
    pub sign: Rule,
    pub derive_viewing: Rule,
    pub derive_nullifier: Rule,
    pub sign_usage_violation: Rule,
    pub derive_usage_violation: Rule,
}

fn secret_key(secret: &[u8; 32]) -> p256::SecretKey {
    p256::SecretKey::from_slice(secret).expect("valid P-256 root scalar")
}

fn get_public_key_rule(key_id: &'static str, secret: &[u8; 32], usage: KeyUsageType) -> Rule {
    let spki = codec::spki_from_p256(&P256Pubkey::from_p256(&secret_key(secret).public_key()));
    mock!(Client::get_public_key)
        .match_requests(move |request| request.key_id() == Some(key_id))
        .then_output(move || {
            let output = GetPublicKeyOutput::builder()
                .key_id(key_id)
                .public_key(Blob::new(spki.clone()))
                .key_spec(KeySpec::EccNistP256)
                .key_usage(usage.clone());
            match usage {
                KeyUsageType::SignVerify => output
                    .signing_algorithms(SigningAlgorithmSpec::EcdsaSha256)
                    .build(),
                _ => output
                    .key_agreement_algorithms(KeyAgreementAlgorithmSpec::Ecdh)
                    .build(),
            }
        })
}

fn matches_p256_digest_sign(request: &SignInput, key_id: &'static str) -> bool {
    request.key_id() == Some(key_id)
        && request.message_type() == Some(&MessageType::Digest)
        && request.signing_algorithm() == Some(&SigningAlgorithmSpec::EcdsaSha256)
        && request
            .message()
            .is_some_and(|message| message.as_ref().len() == 32)
}

fn sign_rule(secret: &[u8; 32], force_high_s: bool) -> Rule {
    let signing_key = p256::ecdsa::SigningKey::from(&secret_key(secret));
    mock!(Client::sign)
        .match_requests(|request| matches_p256_digest_sign(request, SIGN_KEY_ID))
        .then_compute_output(move |request| {
            let digest = request.message().expect("sign request carries a message");
            let signature: p256::ecdsa::Signature = signing_key
                .sign_prehash(digest.as_ref())
                .expect("P-256 prehash signing");
            let der = if force_high_s {
                codec::der_from_compact_high_s(&signature.to_bytes().into())
            } else {
                signature.to_der().as_bytes().to_vec()
            };
            SignOutput::builder()
                .key_id(SIGN_KEY_ID)
                .signature(Blob::new(der))
                .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
                .build()
        })
}

fn derive_shared_secret_rule(key_id: &'static str, secret: &[u8; 32]) -> Rule {
    let secret = secret_key(secret);
    mock!(Client::derive_shared_secret)
        .match_requests(move |request| {
            request.key_id() == Some(key_id)
                && request.key_agreement_algorithm() == Some(&KeyAgreementAlgorithmSpec::Ecdh)
        })
        .then_compute_output(move |request| {
            let peer = request
                .public_key()
                .expect("derive request carries a peer key");
            let peer = codec::p256_from_spki(peer.as_ref())
                .to_p256()
                .expect("valid peer point");
            let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
            DeriveSharedSecretOutput::builder()
                .key_id(key_id)
                .shared_secret(Blob::new(shared.raw_secret_bytes().to_vec()))
                .key_agreement_algorithm(KeyAgreementAlgorithmSpec::Ecdh)
                .key_origin(OriginType::AwsKms)
                .build()
        })
}

fn sign_usage_violation_rule() -> Rule {
    mock!(Client::sign)
        .match_requests(|request| {
            request.key_id() == Some(VIEWING_KEY_ID) || request.key_id() == Some(NULLIFIER_KEY_ID)
        })
        .then_error(|| {
            SignError::InvalidKeyUsageException(
                InvalidKeyUsageException::builder()
                    .message("KeyUsage is KEY_AGREEMENT")
                    .build(),
            )
        })
}

fn derive_usage_violation_rule() -> Rule {
    mock!(Client::derive_shared_secret)
        .match_requests(|request| request.key_id() == Some(SIGN_KEY_ID))
        .then_error(|| {
            DeriveSharedSecretError::InvalidKeyUsageException(
                InvalidKeyUsageException::builder()
                    .message("KeyUsage is SIGN_VERIFY")
                    .build(),
            )
        })
}

fn client_with_rules(roots: &P256Roots, force_high_s: bool) -> (Client, P256Rules) {
    let rules = P256Rules {
        get_public_key_sign: get_public_key_rule(
            SIGN_KEY_ID,
            &roots.sign,
            KeyUsageType::SignVerify,
        ),
        get_public_key_viewing: get_public_key_rule(
            VIEWING_KEY_ID,
            &roots.viewing,
            KeyUsageType::KeyAgreement,
        ),
        get_public_key_nullifier: get_public_key_rule(
            NULLIFIER_KEY_ID,
            &roots.nullifier,
            KeyUsageType::KeyAgreement,
        ),
        sign: sign_rule(&roots.sign, force_high_s),
        derive_viewing: derive_shared_secret_rule(VIEWING_KEY_ID, &roots.viewing),
        derive_nullifier: derive_shared_secret_rule(NULLIFIER_KEY_ID, &roots.nullifier),
        sign_usage_violation: sign_usage_violation_rule(),
        derive_usage_violation: derive_usage_violation_rule(),
    };
    let client = mock_client!(
        aws_sdk_kms,
        RuleMode::MatchAny,
        [
            &rules.get_public_key_sign,
            &rules.get_public_key_viewing,
            &rules.get_public_key_nullifier,
            &rules.sign,
            &rules.derive_viewing,
            &rules.derive_nullifier,
            &rules.sign_usage_violation,
            &rules.derive_usage_violation
        ]
    );
    (client, rules)
}

pub fn p256_client(roots: &P256Roots) -> (Client, P256Rules) {
    client_with_rules(roots, false)
}

pub fn p256_client_high_s(roots: &P256Roots) -> (Client, P256Rules) {
    client_with_rules(roots, true)
}

pub struct KmsP256ShieldedKeypair {
    runtime: tokio::runtime::Runtime,
    client: Client,
    sign_key_id: String,
    signing_pubkey: PublicKey,
    viewing_pubkey: P256Pubkey,
    nullifier_key: NullifierKey,
}

impl KmsP256ShieldedKeypair {
    pub fn bootstrap(
        client: Client,
        sign_key_id: &str,
        viewing_key_id: &str,
        nullifier_key_id: &str,
    ) -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("current-thread runtime");

        let sign_output = runtime
            .block_on(client.get_public_key().key_id(sign_key_id).send())
            .expect("GetPublicKey for the sign key succeeds");
        assert_eq!(sign_output.key_spec(), Some(&KeySpec::EccNistP256));
        assert_eq!(sign_output.key_usage(), Some(&KeyUsageType::SignVerify));
        let signing_pubkey = PublicKey::from_p256(&codec::p256_from_spki(
            sign_output.public_key().expect("sign key SPKI").as_ref(),
        ));

        let viewing_output = runtime
            .block_on(client.get_public_key().key_id(viewing_key_id).send())
            .expect("GetPublicKey for the viewing key succeeds");
        assert_eq!(viewing_output.key_spec(), Some(&KeySpec::EccNistP256));
        assert_eq!(
            viewing_output.key_usage(),
            Some(&KeyUsageType::KeyAgreement)
        );
        let viewing_pubkey = codec::p256_from_spki(
            viewing_output
                .public_key()
                .expect("viewing key SPKI")
                .as_ref(),
        );

        let p_derive =
            P256Pubkey::from_bytes(P_DERIVE_SEC1).expect("committed P_derive is valid SEC1");
        let seed = runtime
            .block_on(
                client
                    .derive_shared_secret()
                    .key_id(nullifier_key_id)
                    .key_agreement_algorithm(KeyAgreementAlgorithmSpec::Ecdh)
                    .public_key(Blob::new(codec::spki_from_p256(&p_derive)))
                    .send(),
            )
            .expect("DeriveSharedSecret for the nullifier root succeeds")
            .shared_secret()
            .expect("shared secret blob")
            .as_ref()
            .to_vec();
        let mut nullifier_secret = [0u8; BLINDING_LEN];
        hkdf::Hkdf::<sha2::Sha256>::new(None, &seed)
            .expand(INFO_NF_KEY_ECDH, &mut nullifier_secret)
            .expect("nullifier expand");

        Self {
            runtime,
            client,
            sign_key_id: sign_key_id.to_string(),
            signing_pubkey,
            viewing_pubkey,
            nullifier_key: NullifierKey::from_secret(nullifier_secret),
        }
    }
}

impl ShieldedKeypairTrait for KmsP256ShieldedKeypair {
    fn signing_pubkey(&self) -> PublicKey {
        self.signing_pubkey
    }

    fn viewing_pubkey(&self) -> P256Pubkey {
        self.viewing_pubkey
    }

    fn curve(&self) -> Curve {
        Curve::P256
    }

    fn shielded_address(&self) -> Result<ShieldedAddress, KeypairError> {
        Ok(ShieldedAddress {
            signing_pubkey: self.signing_pubkey,
            nullifier_pubkey: self.nullifier_key.pubkey()?,
            viewing_pubkey: self.viewing_pubkey,
        })
    }

    fn owner_hash(&self) -> Result<[u8; 32], KeypairError> {
        hash::owner_hash(&self.signing_pubkey, &self.nullifier_key.pubkey()?)
    }

    fn compressed_address(&self) -> Result<CompressedShieldedAddress, KeypairError> {
        Ok(CompressedShieldedAddress {
            owner_hash: self.owner_hash()?,
            viewing_pubkey: self.viewing_pubkey,
        })
    }

    fn sign_message(&self, message: &[u8]) -> Result<[u8; 64], KeypairError> {
        if derivation::is_derivation_input(message) {
            return Err(KeypairError::DerivationInput);
        }
        self.sign_hash(&hash::sha256(message))
    }

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<[u8; 64], KeypairError> {
        if derivation::is_derivation_input(hash) {
            return Err(KeypairError::DerivationInput);
        }
        let output = self
            .runtime
            .block_on(
                self.client
                    .sign()
                    .key_id(&self.sign_key_id)
                    .message(Blob::new(hash.to_vec()))
                    .message_type(MessageType::Digest)
                    .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
                    .send(),
            )
            .map_err(|_| KeypairError::SigningFailed)?;
        let der = output.signature().ok_or(KeypairError::SigningFailed)?;
        Ok(codec::compact_low_s_from_der(der.as_ref()))
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
